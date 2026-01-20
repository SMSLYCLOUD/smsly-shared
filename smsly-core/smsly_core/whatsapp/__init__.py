"""
WhatsApp Templates Module
==========================
WhatsApp Business API template management.
"""

# Re-export all public APIs for backwards compatibility
from .models import (
    TemplateCategory,
    TemplateStatus,
    ComponentType,
    TemplateComponent,
    WhatsAppTemplate,
    Session,
)
from .template_manager import TemplateManager
from .session_manager import SessionManager

__all__ = [
    # Models
    "TemplateCategory",
    "TemplateStatus",
    "ComponentType",
    "TemplateComponent",
    "WhatsAppTemplate",
    "Session",
    # Managers
    "TemplateManager",
    "SessionManager",
]
