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

import os
import httpx
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AdminConfig:
    """Configuration for admin backend connection."""
    base_url: str = os.environ.get("ADMIN_BACKEND_URL", "http://localhost:8000")
    staff_api_url: str = os.environ.get("ADMIN_STAFF_API_URL", "http://localhost:8000/api/staff")
    internal_secret: str = os.environ.get("INTERNAL_API_SECRET", "")
    timeout: float = 10.0


class AdminClient:
    """
    Client for microservices to communicate with central Django admin backend.
    
    Features:
    - User verification
    - Usage reporting
    - Feature access checks
    - Configuration fetching
    - License validation
    """
    
    def __init__(self, config: AdminConfig = None):
        self.config = config or AdminConfig()
        self._client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        await self._get_client()
        return self
    
    async def __aexit__(self, *args):
        await self.close()
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                timeout=self.config.timeout,
                headers=self._get_headers()
            )
        return self._client
    
    def _get_headers(self) -> Dict[str, str]:
        return {
            "X-Internal-Secret": self.config.internal_secret,
            "Content-Type": "application/json",
        }
    
    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
    
    # ==========================================
    # USER OPERATIONS
    # ==========================================
    
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information from admin backend."""
        try:
            client = await self._get_client()
            response = await client.get(f"/api/internal/users/{user_id}/")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get user {user_id}: {e}")
            return None
    
    async def get_user_by_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Get user by API key validation."""
        try:
            client = await self._get_client()
            response = await client.post(
                "/api/internal/validate-api-key/",
                json={"api_key": api_key}
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to validate API key: {e}")
            return None
    
    async def get_account_limits(self, user_id: str) -> Dict[str, int]:
        """Get account limits for a user."""
        try:
            client = await self._get_client()
            response = await client.get(f"/api/internal/users/{user_id}/limits/")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get limits for {user_id}: {e}")
            return {}
    
    # ==========================================
    # USAGE REPORTING
    # ==========================================
    
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
    
    # ==========================================
    # FEATURE ACCESS
    # ==========================================
    
    async def check_feature_access(
        self, 
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
    
    # ==========================================
    # CONFIGURATION
    # ==========================================
    
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
    
    # ==========================================
    # BILLING
    # ==========================================
    
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
