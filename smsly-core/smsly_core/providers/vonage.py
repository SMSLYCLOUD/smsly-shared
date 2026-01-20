"""
Vonage (Nexmo) SMS Provider Adapter
====================================
Fallback adapter for Vonage SMS API.
"""

import httpx
from typing import Optional, Dict, Any
import structlog

from smsly_core.adapters import (
    BaseProviderAdapter,
    SendResult,
    WebhookEvent,
    MessageStatus,
)

logger = structlog.get_logger(__name__)


class VonageAdapter(BaseProviderAdapter):
    """
    Vonage SMS provider adapter.
    
    Features:
    - SMS support (global coverage)
    - Webhook signature validation
    - DLR parsing
    """
    
    name = "vonage"
    supports_mms = False
    supports_whatsapp = True
    
    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: {
                "api_key": "xxx",
                "api_secret": "xxx",
                "signature_secret": "xxx",  # for webhook validation
            }
        """
        super().__init__(config)
        self.api_key = config["api_key"]
        self.api_secret = config["api_secret"]
        self.signature_secret = config.get("signature_secret")
        self.base_url = "https://rest.nexmo.com"
        self._client: Optional[httpx.AsyncClient] = None
    
    async def initialize(self) -> None:
        """Create HTTP client."""
        self._client = httpx.AsyncClient(timeout=30.0)
        await super().initialize()
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
        await super().close()
    
    async def send_sms(
        self,
        to: str,
        from_: str,
        body: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send SMS via Vonage."""
        if not self._client:
            raise RuntimeError("Adapter not initialized")
        
        # Remove + from phone numbers
        to_clean = to.lstrip("+")
        from_clean = from_.lstrip("+") if from_.startswith("+") else from_
        
        payload = {
            "api_key": self.api_key,
            "api_secret": self.api_secret,
            "to": to_clean,
            "from": from_clean,
            "text": body,
            "type": "unicode" if any(ord(c) > 127 for c in body) else "text",
        }
        
        # Add callback URL if provided
        if metadata and metadata.get("webhook_url"):
            payload["callback"] = metadata["webhook_url"]
        
        try:
            response = await self._client.post(
                f"{self.base_url}/sms/json",
                data=payload,
            )
            
            data = response.json()
            messages = data.get("messages", [])
            
            if messages and messages[0].get("status") == "0":
                msg = messages[0]
                return SendResult(
                    success=True,
                    provider_message_id=msg["message-id"],
                    status=MessageStatus.SENT,
                    raw_response=data,
                    cost=float(msg.get("message-price", 0)),
                    segments=int(msg.get("message-count", 1)),
                )
            else:
                error = messages[0] if messages else {}
                return SendResult(
                    success=False,
                    status=MessageStatus.FAILED,
                    error_code=error.get("status", "unknown"),
                    error_message=error.get("error-text", "Unknown error"),
                    raw_response=data,
                )
        except Exception as e:
            logger.error("Vonage send failed", error=str(e))
            return SendResult(
                success=False,
                status=MessageStatus.FAILED,
                error_message=str(e),
            )
    
    async def validate_webhook(
        self,
        headers: Dict[str, str],
        body: bytes,
    ) -> bool:
        """Validate Vonage webhook signature."""
        if not self.signature_secret:
            return True  # No signature validation configured
        
        import hmac
        import hashlib
        import json
        
        signature = headers.get("Authorization", "").replace("Bearer ", "")
        
        # Vonage uses JWT or HMAC depending on configuration
        # This is a simplified HMAC check
        try:
            payload = json.loads(body)
            # Sort and serialize
            sig_string = "&".join(f"{k}={v}" for k, v in sorted(payload.items()) if k != "sig")
            
            expected = hmac.new(
                self.signature_secret.encode(),
                sig_string.encode(),
                hashlib.sha256,
            ).hexdigest()
            
            return signature.lower() == expected.lower()
        except Exception:
            return False
    
    async def parse_webhook(self, body: bytes) -> WebhookEvent:
        """Parse Vonage DLR webhook."""
        import json
        
        data = json.loads(body)
        
        # Vonage DLR format
        return WebhookEvent(
            provider_message_id=data.get("messageId", data.get("message-id", "")),
            status=self._map_status(data.get("status", "")),
            timestamp=data.get("message-timestamp"),
            error_code=data.get("err-code"),
            raw_payload=data,
        )
    
    def _map_status(self, vonage_status: str) -> MessageStatus:
        """Map Vonage status to internal status."""
        mapping = {
            "submitted": MessageStatus.PENDING,
            "delivered": MessageStatus.DELIVERED,
            "expired": MessageStatus.FAILED,
            "failed": MessageStatus.FAILED,
            "rejected": MessageStatus.REJECTED,
            "accepted": MessageStatus.SENT,
            "buffered": MessageStatus.PENDING,
        }
        return mapping.get(vonage_status.lower(), MessageStatus.PENDING)
    
    async def health_check(self) -> bool:
        """Check Vonage API availability."""
        if not self._client:
            return False
        
        try:
            response = await self._client.get(
                f"{self.base_url}/account/get-balance",
                params={"api_key": self.api_key, "api_secret": self.api_secret},
            )
            return response.status_code == 200
        except Exception:
            return False
