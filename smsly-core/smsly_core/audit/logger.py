"""
Audit Logger
=============
High-level audit logging interface with hash chain support.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import structlog

from .event_types import AuditEventType
from .models import AuditEvent
from .hashing import compute_event_hash

logger = structlog.get_logger(__name__)


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
        timestamp = datetime.now(timezone.utc)
        payload = payload or {}
        
        # Normalize event type
        event_type_str = (
            event_type.value if isinstance(event_type, AuditEventType) 
            else event_type
        )
        
        # Compute hash with chain
        event_hash = compute_event_hash(
            self._previous_hash,
            timestamp,
            self.service_name,
            event_type_str,
            payload,
        )
        
        event = AuditEvent(
            id=str(uuid.uuid4()),
            timestamp=timestamp,
            service=self.service_name,
            event_type=event_type_str,
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
