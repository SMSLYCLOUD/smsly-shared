"""
Billing Operations
==================
AdminClient methods for billing and configuration.
"""

import logging
from typing import Dict, Any

from .client import AdminClient

logger = logging.getLogger(__name__)


class BillingMixin:
    """Mixin for billing and config operations."""
    
    async def get_product_config(self: AdminClient, product: str) -> Dict[str, Any]:
        """Get product configuration from admin backend."""
        try:
            client = await self._get_client()
            response = await client.get(f"/api/internal/config/products/{product}/")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get config for {product}: {e}")
            return {}
    
    async def get_global_settings(self: AdminClient) -> Dict[str, Any]:
        """Get global platform settings."""
        try:
            client = await self._get_client()
            response = await client.get("/api/internal/config/global/")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get global settings: {e}")
            return {}
    
    async def deduct_balance(
        self: AdminClient, 
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
    
    async def check_balance(
        self: AdminClient,
        user_id: str,
        required: float = 0
    ) -> bool:
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
