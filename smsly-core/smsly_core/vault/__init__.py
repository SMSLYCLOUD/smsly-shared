"""SMSLY Vault integration module."""

from .client import (
    SMSLYVault,
    get_vault,
    get_secret,
    get_database_url,
    get_api_key,
)

__all__ = [
    "SMSLYVault",
    "get_vault",
    "get_secret",
    "get_database_url",
    "get_api_key",
]
