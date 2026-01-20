"""
WhatsApp Templates Module
==========================
WhatsApp Business API template management.
"""

from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
import structlog

logger = structlog.get_logger(__name__)


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


class TemplateManager:
    """
    Manages WhatsApp message templates.
    
    Templates must be approved by Meta before use.
    """
    
    def __init__(self, waba_id: str, access_token: str):
        self.waba_id = waba_id
        self.access_token = access_token
        self.base_url = f"https://graph.facebook.com/v18.0/{waba_id}"
        self._templates: Dict[str, WhatsAppTemplate] = {}
    
    async def sync_templates(self) -> List[WhatsAppTemplate]:
        """
        Fetch all templates from Meta.
        
        Returns:
            List of templates
        """
        import httpx
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/message_templates",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )
            
            if response.status_code != 200:
                logger.error("Failed to fetch templates", status=response.status_code)
                return []
            
            data = response.json()
            templates = []
            
            for item in data.get("data", []):
                template = WhatsAppTemplate(
                    id=item["id"],
                    name=item["name"],
                    language=item["language"],
                    category=TemplateCategory(item["category"]),
                    status=TemplateStatus(item["status"]),
                    components=[
                        TemplateComponent(
                            type=ComponentType(c["type"]),
                            text=c.get("text"),
                            format=c.get("format"),
                        )
                        for c in item.get("components", [])
                    ],
                )
                templates.append(template)
                self._templates[f"{template.name}:{template.language}"] = template
            
            logger.info("Templates synced", count=len(templates))
            return templates
    
    async def create_template(self, template: WhatsAppTemplate) -> WhatsAppTemplate:
        """
        Submit a template for approval.
        
        Args:
            template: Template to create
            
        Returns:
            Created template with ID
        """
        import httpx
        
        payload = {
            "name": template.name,
            "language": template.language,
            "category": template.category.value,
            "components": [
                {
                    "type": c.type.value,
                    "text": c.text,
                    "format": c.format,
                }
                for c in template.components
                if c.type != ComponentType.BUTTONS
            ],
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/message_templates",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json=payload,
            )
            
            if response.status_code == 200:
                data = response.json()
                template.id = data["id"]
                template.status = TemplateStatus.PENDING
                template.created_at = datetime.utcnow()
                
                self._templates[f"{template.name}:{template.language}"] = template
                
                logger.info("Template created", name=template.name, id=template.id)
                return template
            else:
                logger.error(
                    "Failed to create template",
                    status=response.status_code,
                    error=response.text,
                )
                raise Exception(f"Template creation failed: {response.text}")
    
    def get_template(self, name: str, language: str = "en") -> Optional[WhatsAppTemplate]:
        """Get a template by name and language."""
        return self._templates.get(f"{name}:{language}")
    
    def get_approved_templates(self) -> List[WhatsAppTemplate]:
        """Get all approved templates."""
        return [
            t for t in self._templates.values()
            if t.status == TemplateStatus.APPROVED
        ]
    
    def render_template(
        self,
        template: WhatsAppTemplate,
        parameters: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """
        Render a template with parameters for sending.
        
        Args:
            template: The template to render
            parameters: Parameters for each component type
            
        Returns:
            WhatsApp API message payload
        """
        components = []
        
        for component in template.components:
            comp_params = parameters.get(component.type.value.lower(), [])
            
            if comp_params:
                components.append({
                    "type": component.type.value.lower(),
                    "parameters": [
                        {"type": "text", "text": p} for p in comp_params
                    ],
                })
        
        return {
            "type": "template",
            "template": {
                "name": template.name,
                "language": {"code": template.language},
                "components": components,
            },
        }


@dataclass
class Session:
    """WhatsApp 24-hour session window."""
    phone: str
    window_start: datetime
    window_end: datetime
    is_active: bool = True
    last_message_at: Optional[datetime] = None


class SessionManager:
    """
    Manages WhatsApp 24-hour session windows.
    
    Messages outside the session window require templates.
    """
    
    def __init__(self):
        self._sessions: Dict[str, Session] = {}
    
    def get_or_create_session(self, phone: str) -> Session:
        """Get existing session or create new one."""
        if phone in self._sessions:
            session = self._sessions[phone]
            if session.is_active and datetime.utcnow() < session.window_end:
                return session
        
        # Create new session
        now = datetime.utcnow()
        from datetime import timedelta
        session = Session(
            phone=phone,
            window_start=now,
            window_end=now + timedelta(hours=24),
        )
        self._sessions[phone] = session
        return session
    
    def is_in_session(self, phone: str) -> bool:
        """Check if a phone number is in an active session."""
        if phone not in self._sessions:
            return False
        
        session = self._sessions[phone]
        return session.is_active and datetime.utcnow() < session.window_end
    
    def extend_session(self, phone: str) -> Session:
        """Extend session window on user message."""
        session = self.get_or_create_session(phone)
        
        now = datetime.utcnow()
        from datetime import timedelta
        session.window_end = now + timedelta(hours=24)
        session.last_message_at = now
        
        return session
    
    def invalidate_session(self, phone: str) -> None:
        """Invalidate a session."""
        if phone in self._sessions:
            self._sessions[phone].is_active = False
