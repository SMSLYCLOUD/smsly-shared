"""
Twilio SMS Provider Adapter
============================
Production adapter for Twilio SMS/MMS API.
"""

import httpx
from typing import Optional, Dict, Any, List
from base64 import b64encode
import structlog

from smsly_core.adapters import (
    BaseProviderAdapter,
    SendResult,
    WebhookEvent,
    MessageStatus,
)

logger = structlog.get_logger(__name__)


class TwilioAdapter(BaseProviderAdapter):
    """
    Twilio SMS/MMS provider adapter.
    
    Features:
    - SMS and MMS support
    - Webhook signature validation
    - Status callback parsing
    """
    
    name = "twilio"
    supports_mms = True
    supports_whatsapp = True
    
    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: {
                "account_sid": "ACxxx",
                "auth_token": "xxx",
                "messaging_service_sid": "MGxxx",  # optional
            }
        """
        super().__init__(config)
        self.account_sid = config["account_sid"]
        self.auth_token = config["auth_token"]
        self.messaging_service_sid = config.get("messaging_service_sid")
        self.base_url = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}"
        self._client: Optional[httpx.AsyncClient] = None
    
    async def initialize(self) -> None:
        """Create HTTP client with auth."""
        auth = b64encode(f"{self.account_sid}:{self.auth_token}".encode()).decode()
        self._client = httpx.AsyncClient(
            headers={"Authorization": f"Basic {auth}"},
            timeout=30.0,
        )
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
        """Send SMS via Twilio."""
        if not self._client:
            raise RuntimeError("Adapter not initialized")
        
        payload = {
            "To": to,
            "Body": body,
        }
        
        if self.messaging_service_sid:
            payload["MessagingServiceSid"] = self.messaging_service_sid
        else:
            payload["From"] = from_
        
        # Add status callback if provided
        if metadata and metadata.get("webhook_url"):
            payload["StatusCallback"] = metadata["webhook_url"]
        
        try:
            response = await self._client.post(
                f"{self.base_url}/Messages.json",
                data=payload,
            )
            
            if response.status_code == 201:
                data = response.json()
                return SendResult(
                    success=True,
                    provider_message_id=data["sid"],
                    status=self._map_status(data["status"]),
                    raw_response=data,
                    segments=int(data.get("num_segments", 1)),
                )
            else:
                error_data = response.json()
                return SendResult(
                    success=False,
                    status=MessageStatus.FAILED,
                    error_code=str(error_data.get("code", response.status_code)),
                    error_message=error_data.get("message", "Unknown error"),
                    raw_response=error_data,
                )
        except Exception as e:
            logger.error("Twilio send failed", error=str(e))
            return SendResult(
                success=False,
                status=MessageStatus.FAILED,
                error_message=str(e),
            )
    
    async def send_mms(
        self,
        to: str,
        from_: str,
        text: Optional[str],
        media_urls: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send MMS via Twilio."""
        if not self._client:
            raise RuntimeError("Adapter not initialized")
        
        payload = {
            "To": to,
        }
        
        if self.messaging_service_sid:
            payload["MessagingServiceSid"] = self.messaging_service_sid
        else:
            payload["From"] = from_
        
        if text:
            payload["Body"] = text
        
        # Twilio accepts multiple MediaUrl parameters
        for url in media_urls:
            payload.setdefault("MediaUrl", []).append(url)
        
        try:
            response = await self._client.post(
                f"{self.base_url}/Messages.json",
                data=payload,
            )
            
            if response.status_code == 201:
                data = response.json()
                return SendResult(
                    success=True,
                    provider_message_id=data["sid"],
                    status=self._map_status(data["status"]),
                    raw_response=data,
                )
            else:
                error_data = response.json()
                return SendResult(
                    success=False,
                    status=MessageStatus.FAILED,
                    error_code=str(error_data.get("code")),
                    error_message=error_data.get("message"),
                    raw_response=error_data,
                )
        except Exception as e:
            logger.error("Twilio MMS send failed", error=str(e))
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
        """Validate Twilio webhook signature."""
        import hmac
        import hashlib
        from urllib.parse import urlencode, parse_qs
        
        signature = headers.get("X-Twilio-Signature", "")
        url = headers.get("X-Original-Url", "")  # Must be set by gateway
        
        # Parse form data
        params = parse_qs(body.decode())
        sorted_params = sorted((k, v[0]) for k, v in params.items())
        
        # Build signature string
        sig_string = url + urlencode(sorted_params)
        
        # Compute HMAC
        expected = hmac.new(
            self.auth_token.encode(),
            sig_string.encode(),
            hashlib.sha1,
        ).digest()
        
        import base64
        expected_b64 = base64.b64encode(expected).decode()
        
        return hmac.compare_digest(signature, expected_b64)
    
    async def parse_webhook(self, body: bytes) -> WebhookEvent:
        """Parse Twilio status callback."""
        from urllib.parse import parse_qs
        
        params = parse_qs(body.decode())
        
        return WebhookEvent(
            provider_message_id=params.get("MessageSid", [""])[0],
            status=self._map_status(params.get("MessageStatus", [""])[0]),
            error_code=params.get("ErrorCode", [None])[0],
            error_message=params.get("ErrorMessage", [None])[0],
            raw_payload=params,
        )
    
    def _map_status(self, twilio_status: str) -> MessageStatus:
        """Map Twilio status to internal status."""
        mapping = {
            "queued": MessageStatus.PENDING,
            "sending": MessageStatus.PENDING,
            "sent": MessageStatus.SENT,
            "delivered": MessageStatus.DELIVERED,
            "undelivered": MessageStatus.FAILED,
            "failed": MessageStatus.FAILED,
        }
        return mapping.get(twilio_status.lower(), MessageStatus.PENDING)
    
    async def health_check(self) -> bool:
        """Check Twilio API availability."""
        if not self._client:
            return False
        
        try:
            response = await self._client.get(f"{self.base_url}.json")
            return response.status_code == 200
        except Exception:
            return False
