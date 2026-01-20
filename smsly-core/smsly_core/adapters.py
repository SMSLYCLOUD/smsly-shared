"""
Unified Provider Adapter Module
================================
Base classes for SMS/MMS/WhatsApp/RCS provider integrations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class MessageStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    REJECTED = "rejected"


@dataclass
class SendResult:
    """Result of a message send operation."""
    success: bool
    provider_message_id: Optional[str] = None
    status: MessageStatus = MessageStatus.PENDING
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    raw_response: Optional[Dict[str, Any]] = None
    cost: Optional[float] = None
    segments: int = 1


@dataclass
class WebhookEvent:
    """Parsed webhook event from a provider."""
    provider_message_id: str
    status: MessageStatus
    timestamp: Optional[float] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None


class BaseProviderAdapter(ABC):
    """
    Abstract base class for messaging provider adapters.
    
    All provider implementations (Twilio, Vonage, etc.) should inherit from this.
    """
    
    name: str = "base"
    supports_mms: bool = False
    supports_whatsapp: bool = False
    supports_rcs: bool = False
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the adapter with provider-specific configuration.
        
        Args:
            config: Provider-specific config (API keys, account IDs, etc.)
        """
        self.config = config
        self._is_initialized = False
    
    async def initialize(self) -> None:
        """Initialize the adapter (e.g., create HTTP clients)."""
        self._is_initialized = True
        logger.info(f"Provider adapter initialized", provider=self.name)
    
    async def close(self) -> None:
        """Clean up resources (e.g., close HTTP clients)."""
        self._is_initialized = False
        logger.info(f"Provider adapter closed", provider=self.name)
    
    @abstractmethod
    async def send_sms(
        self,
        to: str,
        from_: str,
        body: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """
        Send an SMS message.
        
        Args:
            to: Recipient phone number (E.164 format)
            from_: Sender phone number or alphanumeric ID
            body: Message content
            metadata: Optional metadata for tracking
        
        Returns:
            SendResult with provider response
        """
        pass
    
    async def send_mms(
        self,
        to: str,
        from_: str,
        text: Optional[str],
        media_urls: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """
        Send an MMS message.
        
        Default implementation raises NotImplementedError.
        Override in providers that support MMS.
        """
        raise NotImplementedError(f"{self.name} does not support MMS")
    
    async def validate_webhook(
        self,
        headers: Dict[str, str],
        body: bytes,
    ) -> bool:
        """
        Validate webhook signature from provider.
        
        Args:
            headers: HTTP headers from webhook request
            body: Raw request body
        
        Returns:
            True if signature is valid
        """
        return True  # Override in providers with signature verification
    
    async def parse_webhook(self, body: bytes) -> WebhookEvent:
        """
        Parse webhook payload into a standardized WebhookEvent.
        
        Args:
            body: Raw request body
        
        Returns:
            Parsed WebhookEvent
        """
        raise NotImplementedError(f"{self.name} must implement webhook parsing")
    
    async def health_check(self) -> bool:
        """
        Check if the provider is reachable.
        
        Returns:
            True if provider API is healthy
        """
        return self._is_initialized


class ProviderRegistry:
    """Registry for managing multiple provider adapters."""
    
    def __init__(self):
        self._adapters: Dict[str, BaseProviderAdapter] = {}
    
    def register(self, adapter: BaseProviderAdapter) -> None:
        """Register a provider adapter."""
        self._adapters[adapter.name.lower()] = adapter
        logger.info("Provider registered", provider=adapter.name)
    
    def get(self, name: str) -> BaseProviderAdapter:
        """Get a provider adapter by name."""
        adapter = self._adapters.get(name.lower())
        if not adapter:
            raise ValueError(f"Unknown provider: {name}")
        return adapter
    
    def list(self) -> List[str]:
        """List all registered provider names."""
        return list(self._adapters.keys())
    
    async def close_all(self) -> None:
        """Close all registered adapters."""
        for adapter in self._adapters.values():
            await adapter.close()


# Global registry instance
provider_registry = ProviderRegistry()
