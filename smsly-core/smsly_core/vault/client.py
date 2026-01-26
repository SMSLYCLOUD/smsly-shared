"""
HashiCorp Vault Client for SMSLY Services
==========================================

Usage:
    from smsly_vault import SMSLYVault
    
    vault = SMSLYVault()
    
    # Get API keys
    termii_keys = vault.get_secret("termii")
    api_key = termii_keys["API_KEY"]
    
    # Get rotating keys
    current_key = vault.get_rotating_key()
"""

import os
import hvac
from typing import Optional, Dict, Any
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


class SMSLYVault:
    """HashiCorp Vault client for SMSLY platform services."""
    
    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        mount_point: str = "smsly"
    ):
        self.url = url or os.environ.get("VAULT_ADDR", "https://vault.smsly.cloud")
        self.token = token or os.environ.get("VAULT_TOKEN")
        self.mount_point = mount_point
        self._client: Optional[hvac.Client] = None
        
    @property
    def client(self) -> hvac.Client:
        """Lazy-loaded Vault client."""
        if self._client is None:
            self._client = hvac.Client(url=self.url, token=self.token)
            if not self._client.is_authenticated():
                raise ValueError("Vault authentication failed. Check VAULT_TOKEN.")
        return self._client
    
    def get_secret(self, path: str, version: Optional[int] = None) -> Dict[str, Any]:
        """
        Get a secret from Vault KV v2.
        
        Args:
            path: Secret path (e.g., "termii", "postgres", "redis")
            version: Optional specific version to retrieve
            
        Returns:
            Dictionary of secret key-value pairs
        """
        try:
            secret = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.mount_point,
                version=version
            )
            return secret["data"]["data"]
        except hvac.exceptions.InvalidPath:
            logger.error(f"Secret not found at path: {self.mount_point}/{path}")
            raise
        except Exception as e:
            logger.error(f"Failed to get secret from Vault: {e}")
            raise
    
    def set_secret(self, path: str, data: Dict[str, Any]) -> None:
        """
        Store a secret in Vault KV v2.
        
        Args:
            path: Secret path
            data: Dictionary of key-value pairs to store
        """
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                mount_point=self.mount_point
            )
            logger.info(f"Secret stored at {self.mount_point}/{path}")
        except Exception as e:
            logger.error(f"Failed to store secret in Vault: {e}")
            raise
    
    def get_rotating_key(self, key_type: str = "api") -> str:
        """
        Get the current rotating key.
        
        Args:
            key_type: Type of key ("api", "encryption", "signing")
            
        Returns:
            Current active key
        """
        secret = self.get_secret(f"rotating-keys/{key_type}")
        return secret.get("current_key", "")
    
    def rotate_key(self, key_type: str, new_key: str) -> None:
        """
        Rotate a key - moves current to previous and sets new current.
        
        Args:
            key_type: Type of key to rotate
            new_key: The new key value
        """
        import datetime
        
        path = f"rotating-keys/{key_type}"
        
        # Get current key (will become previous)
        try:
            current = self.get_secret(path)
            previous_key = current.get("current_key", "")
        except:
            previous_key = ""
        
        # Store with rotation timestamp
        self.set_secret(path, {
            "current_key": new_key,
            "previous_key": previous_key,
            "rotated_at": datetime.datetime.utcnow().isoformat()
        })
        logger.info(f"Key rotated for {key_type}")
    
    def get_database_url(self, db_name: str = "postgres") -> str:
        """
        Get database connection URL from Vault.
        
        Args:
            db_name: Name of database secret (e.g., "postgres", "redis")
            
        Returns:
            Database connection URL
        """
        secret = self.get_secret(f"databases/{db_name}")
        
        if db_name == "redis":
            return f"redis://:{secret['password']}@{secret['host']}:{secret.get('port', 6379)}"
        else:
            return f"postgresql://{secret['username']}:{secret['password']}@{secret['host']}:{secret.get('port', 5432)}/{secret.get('database', db_name)}"
    
    def get_api_credentials(self, service: str) -> Dict[str, str]:
        """
        Get API credentials for external services.
        
        Args:
            service: Service name (e.g., "termii", "twilio", "stripe")
            
        Returns:
            Dictionary with API credentials
        """
        return self.get_secret(f"api-keys/{service}")


# Singleton instance for convenience
_vault_instance: Optional[SMSLYVault] = None


def get_vault() -> SMSLYVault:
    """Get the global Vault client instance."""
    global _vault_instance
    if _vault_instance is None:
        _vault_instance = SMSLYVault()
    return _vault_instance


# Convenience functions
def get_secret(path: str) -> Dict[str, Any]:
    """Get a secret from Vault."""
    return get_vault().get_secret(path)


def get_database_url(db_name: str = "postgres") -> str:
    """Get database URL from Vault."""
    return get_vault().get_database_url(db_name)


def get_api_key(service: str) -> str:
    """Get API key for a service."""
    creds = get_vault().get_api_credentials(service)
    return creds.get("API_KEY", creds.get("api_key", ""))
