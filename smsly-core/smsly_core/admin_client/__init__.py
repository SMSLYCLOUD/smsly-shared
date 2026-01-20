"""
SMSLY Admin Backend Client
==========================
Client for microservices to communicate with the central Django admin backend.

Usage:
    from smsly_core.admin_client import AdminClient
    
    client = AdminClient()
    
    # Get user info
    user = await client.get_user(user_id)
    
    # Report usage
    await client.report_usage(user_id, "sms", 5)
    
    # Check feature access
    can_use = await client.check_feature_access(user_id, "mms")
"""

from typing import Optional, Dict, Any
import logging

from .config import AdminConfig
from .client import AdminClient as BaseAdminClient

logger = logging.getLogger(__name__)


# Extended AdminClient with all operations
class AdminClient(BaseAdminClient):
    """Full AdminClient with all operations."""
    
    # Usage operations
    async def report_usage(
        self, 
        user_id: str, 
        product: str, 
        quantity: int,
        metadata: Dict[str, Any] = None
    ) -> bool:
        """Report product usage to admin backend."""
        try:
            client = await self._get_client()
            response = await client.post(
                "/api/internal/usage/report/",
                json={
                    "user_id": user_id,
                    "product": product,
                    "quantity": quantity,
                    "metadata": metadata or {}
                }
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to report usage for {user_id}: {e}")
            return False
    
    async def get_usage(self, user_id: str, product: str = None) -> Dict[str, Any]:
        """Get current usage stats for a user."""
        try:
            client = await self._get_client()
            url = f"/api/internal/usage/{user_id}/"
            if product:
                url += f"?product={product}"
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get usage for {user_id}: {e}")
            return {}
    
    async def check_feature_access(self, user_id: str, feature: str) -> bool:
        """Check if user has access to a feature."""
        try:
            client = await self._get_client()
            response = await client.post(
                "/api/internal/features/check/",
                json={"user_id": user_id, "feature": feature}
            )
            response.raise_for_status()
            return response.json().get("allowed", False)
        except Exception as e:
            logger.error(f"Failed to check feature access for {user_id}: {e}")
            return False
    
    # Config operations
    async def get_product_config(self, product: str) -> Dict[str, Any]:
        """Get product configuration from admin backend."""
        try:
            client = await self._get_client()
            response = await client.get(f"/api/internal/config/products/{product}/")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get config for {product}: {e}")
            return {}
    
    async def get_global_settings(self) -> Dict[str, Any]:
        """Get global platform settings."""
        try:
            client = await self._get_client()
            response = await client.get("/api/internal/config/global/")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get global settings: {e}")
            return {}
    
    # Billing operations
    async def deduct_balance(
        self, 
        user_id: str, 
        amount: float, 
        description: str,
        product: str = None
    ) -> bool:
        """Deduct balance from user account."""
        try:
            client = await self._get_client()
            response = await client.post(
                "/api/internal/billing/deduct/",
                json={
                    "user_id": user_id,
                    "amount": amount,
                    "description": description,
                    "product": product
                }
            )
            response.raise_for_status()
            return response.json().get("success", False)
        except Exception as e:
            logger.error(f"Failed to deduct balance for {user_id}: {e}")
            return False
    
    async def check_balance(self, user_id: str, required: float = 0) -> bool:
        """Check if user has sufficient balance."""
        try:
            client = await self._get_client()
            response = await client.get(
                f"/api/internal/billing/check/{user_id}/",
                params={"required": required}
            )
            response.raise_for_status()
            return response.json().get("sufficient", False)
        except Exception as e:
            logger.error(f"Failed to check balance for {user_id}: {e}")
            return False


# Singleton instance
_admin_client: Optional[AdminClient] = None


def get_admin_client() -> AdminClient:
    """Get or create singleton admin client instance."""
    global _admin_client
    if _admin_client is None:
        _admin_client = AdminClient()
    return _admin_client


__all__ = [
    "AdminConfig",
    "AdminClient",
    "get_admin_client",
]
