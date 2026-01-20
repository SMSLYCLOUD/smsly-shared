"""
WhatsApp Models
===============
Data models and enums for WhatsApp Business API.
"""

from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass
from datetime import datetime


class TemplateCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    MARKETING = "MARKETING"
    UTILITY = "UTILITY"


class TemplateStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DISABLED = "DISABLED"


class ComponentType(str, Enum):
    HEADER = "HEADER"
    BODY = "BODY"
    FOOTER = "FOOTER"
    BUTTONS = "BUTTONS"


@dataclass
class TemplateComponent:
    """A component of a WhatsApp template."""
    type: ComponentType
    text: Optional[str] = None
    format: Optional[str] = None  # TEXT, IMAGE, VIDEO, DOCUMENT
    example: Optional[Dict[str, Any]] = None


@dataclass
class WhatsAppTemplate:
    """WhatsApp message template."""
    name: str
    language: str
    category: TemplateCategory
    components: List[TemplateComponent]
    status: TemplateStatus = TemplateStatus.PENDING
    id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class Session:
    """WhatsApp 24-hour session window."""
    phone: str
    window_start: datetime
    window_end: datetime
    is_active: bool = True
    last_message_at: Optional[datetime] = None
