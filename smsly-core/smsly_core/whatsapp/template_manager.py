"""
Template Manager
================
WhatsApp message template management.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import structlog

from .models import (
    WhatsAppTemplate,
    TemplateComponent,
    TemplateCategory,
    TemplateStatus,
    ComponentType,
)

logger = structlog.get_logger(__name__)


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
        """Fetch all templates from Meta."""
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
        """Submit a template for approval."""
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
                logger.error("Failed to create template", status=response.status_code)
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
        """Render a template with parameters for sending."""
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
