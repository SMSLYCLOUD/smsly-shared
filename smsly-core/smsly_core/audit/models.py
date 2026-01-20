"""
Audit Models
=============
Data models for audit log entries.
"""

from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


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
