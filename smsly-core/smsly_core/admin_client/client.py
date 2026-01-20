"""
Admin Client Core
=================
Core AdminClient class for microservice communication with admin backend.
"""

import httpx
import logging
from typing import Optional, Dict, Any

from .config import AdminConfig

logger = logging.getLogger(__name__)


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
    
    # User Operations
    
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
