"""
Direct Access Protection
========================
Protects microservices from direct access attempts that bypass the Security Gateway.

Behavior:
- 1st attempt: Warning with proper URL guidance
- 2nd attempt: Final warning
- 3rd attempt: Block and blacklist the IP
- Subsequent attempts: Immediate block

Uses Redis for distributed tracking across all microservices.
"""

# Re-export all public APIs for backwards compatibility
from .config import (
    GATEWAY_IPS,
    GATEWAY_URL,
    SERVICE_NAME,
    MAX_WARNINGS,
    BLACKLIST_DURATION_HOURS,
    INTERNAL_PREFIXES,
    DEFAULT_EXCLUDED_PATHS,
)

from .ip_utils import is_internal_ip, is_gateway_ip

from .middleware import DirectAccessProtectionMiddleware

from .stats import get_direct_access_stats

__all__ = [
    # Config
    "GATEWAY_IPS",
    "GATEWAY_URL",
    "SERVICE_NAME",
    "MAX_WARNINGS",
    "BLACKLIST_DURATION_HOURS",
    "INTERNAL_PREFIXES",
    "DEFAULT_EXCLUDED_PATHS",
    # IP Utils
    "is_internal_ip",
    "is_gateway_ip",
    # Middleware
    "DirectAccessProtectionMiddleware",
    # Stats
    "get_direct_access_stats",
]
