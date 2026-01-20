"""
Audit Logging Module
====================
Append-only, tamper-evident audit trail with hash chaining.
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class AuditEventType(str, Enum):
    """Standard audit event types across all services."""
    # Authentication
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_FAILED = "auth.failed"
    AUTH_TOKEN_REFRESH = "auth.token_refresh"
    
    # API Keys
    APIKEY_CREATED = "apikey.created"
    APIKEY_ROTATED = "apikey.rotated"
    APIKEY_REVOKED = "apikey.revoked"
    APIKEY_USED = "apikey.used"
    
    # Messaging
    MESSAGE_SENT = "message.sent"
    MESSAGE_DELIVERED = "message.delivered"
    MESSAGE_FAILED = "message.failed"
    
    # Verification
    VERIFY_STARTED = "verify.started"
    VERIFY_COMPLETED = "verify.completed"
    VERIFY_FAILED = "verify.failed"
    
    # Campaigns
    CAMPAIGN_CREATED = "campaign.created"
    CAMPAIGN_STARTED = "campaign.started"
    CAMPAIGN_PAUSED = "campaign.paused"
    CAMPAIGN_COMPLETED = "campaign.completed"
    
    # Admin
    ADMIN_ACTION = "admin.action"
    CONFIG_CHANGED = "config.changed"
    USER_CREATED = "user.created"
    USER_MODIFIED = "user.modified"
    
    # Security
    SECURITY_BLOCK = "security.block"
    SECURITY_ALERT = "security.alert"
    RATE_LIMIT_HIT = "security.rate_limit"


@dataclass
class AuditEvent:
    """An audit log entry with hash chain support."""
    id: str
    timestamp: datetime
    service: str
    event_type: str
    actor_id: Optional[str]
    actor_type: str  # "user", "apikey", "system", "service"
    resource_type: Optional[str]
    resource_id: Optional[str]
    action: str
    outcome: str  # "success", "failure", "blocked"
    payload: Dict[str, Any]
    ip_address: Optional[str]
    user_agent: Optional[str]
    hash: str
    previous_hash: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d


def compute_event_hash(
    previous_hash: Optional[str],
    timestamp: datetime,
    service: str,
    event_type: str,
    payload: Dict[str, Any],
) -> str:
    """
    Compute the hash for an audit event.
    
    Creates a cryptographic chain where each event's hash depends on:
    - The previous event's hash
    - The event's timestamp
    - The service name
    - The event type
    - The payload contents
    
    Args:
        previous_hash: Hash of the previous event (None for first event)
        timestamp: Event timestamp
        service: Service name that generated the event
        event_type: Type of event
        payload: Event payload data
        
    Returns:
        SHA-256 hash of the event
    """
    hash_input = json.dumps({
        "previous_hash": previous_hash,
        "timestamp": timestamp.isoformat(),
        "service": service,
        "event_type": event_type,
        "payload": payload,
    }, sort_keys=True, separators=(',', ':'))
    
    return hashlib.sha256(hash_input.encode()).hexdigest()


def verify_chain_integrity(events: List[AuditEvent]) -> tuple[bool, Optional[int]]:
    """
    Verify the integrity of an audit event chain.
    
    Args:
        events: List of events in chronological order
        
    Returns:
        Tuple of (is_valid, first_invalid_index)
        - is_valid: True if the chain is intact
        - first_invalid_index: Index of first corrupt event, or None
    """
    if not events:
        return True, None
    
    # First event should have no previous hash
    if events[0].previous_hash is not None:
        return False, 0
    
    # Verify each event's hash
    for i, event in enumerate(events):
        expected_hash = compute_event_hash(
            event.previous_hash,
            event.timestamp,
            event.service,
            event.event_type,
            event.payload,
        )
        
        if event.hash != expected_hash:
            logger.warning(
                "Audit chain integrity violation",
                event_id=event.id,
                index=i,
                expected_hash=expected_hash[:16],
                actual_hash=event.hash[:16],
            )
            return False, i
    
    # Verify chain linkage
    for i in range(1, len(events)):
        if events[i].previous_hash != events[i-1].hash:
            logger.warning(
                "Audit chain linkage broken",
                event_id=events[i].id,
                index=i,
            )
            return False, i
    
    return True, None


class AuditLogger:
    """
    High-level audit logging interface.
    
    Tracks the previous hash to maintain chain integrity.
    """
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self._previous_hash: Optional[str] = None
        self._buffer: List[AuditEvent] = []
    
    def set_previous_hash(self, hash_value: str) -> None:
        """Set the previous hash (e.g., from database on startup)."""
        self._previous_hash = hash_value
    
    def log(
        self,
        event_type: AuditEventType,
        action: str,
        outcome: str = "success",
        actor_id: Optional[str] = None,
        actor_type: str = "system",
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditEvent:
        """
        Create an audit log entry.
        
        Args:
            event_type: Type of event
            action: Human-readable action description
            outcome: "success", "failure", or "blocked"
            actor_id: ID of the actor (user, apikey, etc.)
            actor_type: Type of actor
            resource_type: Type of affected resource
            resource_id: ID of affected resource
            payload: Additional event data
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            The created AuditEvent
        """
        import uuid
        
        timestamp = datetime.now(timezone.utc)
        payload = payload or {}
        
        # Compute hash with chain
        event_hash = compute_event_hash(
            self._previous_hash,
            timestamp,
            self.service_name,
            event_type.value if isinstance(event_type, AuditEventType) else event_type,
            payload,
        )
        
        event = AuditEvent(
            id=str(uuid.uuid4()),
            timestamp=timestamp,
            service=self.service_name,
            event_type=event_type.value if isinstance(event_type, AuditEventType) else event_type,
            actor_id=actor_id,
            actor_type=actor_type,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            outcome=outcome,
            payload=payload,
            ip_address=ip_address,
            user_agent=user_agent,
            hash=event_hash,
            previous_hash=self._previous_hash,
        )
        
        # Update chain
        self._previous_hash = event_hash
        self._buffer.append(event)
        
        logger.info(
            "Audit event logged",
            event_id=event.id,
            event_type=event.event_type,
            outcome=outcome,
        )
        
        return event
    
    def flush(self) -> List[AuditEvent]:
        """
        Get and clear buffered events.
        
        Returns:
            List of buffered events
        """
        events = self._buffer
        self._buffer = []
        return events
