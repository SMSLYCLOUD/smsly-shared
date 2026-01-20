"""
Usage and Features Operations
=============================
AdminClient methods for usage reporting and feature access.
"""

import logging
from typing import Dict, Any

from .client import AdminClient

logger = logging.getLogger(__name__)


class UsageMixin:
    """Mixin for usage reporting operations."""
    
    async def report_usage(
        self: AdminClient, 
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
    
    async def get_usage(
        self: AdminClient,
        user_id: str,
        product: str = None
    ) -> Dict[str, Any]:
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
    
    async def check_feature_access(
        self: AdminClient, 
        user_id: str, 
        feature: str
    ) -> bool:
        """Check if user has access to a feature."""
        try:
            client = await self._get_client()
            response = await client.post(
                "/api/internal/features/check/",
                json={"user_id": user_id, "feature": feature}
            )
            response.raise_for_status()
            data = response.json()
            return data.get("allowed", False)
        except Exception as e:
            logger.error(f"Failed to check feature access for {user_id}: {e}")
            return False
