"""
Audit Hashing
=============
Hash computation and chain verification for audit logs.
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
import structlog

from .models import AuditEvent

logger = structlog.get_logger(__name__)


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


def verify_chain_integrity(events: List[AuditEvent]) -> Tuple[bool, Optional[int]]:
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
