"""
IP Utility Functions
====================
Utilities for IP address checking and validation.
"""

from .config import INTERNAL_PREFIXES, GATEWAY_IPS


def is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/local."""
    return any(ip.startswith(prefix) for prefix in INTERNAL_PREFIXES)


def is_gateway_ip(ip: str) -> bool:
    """Check if request comes from the Security Gateway."""
    if not ip:
        return False
    
    # Check configured gateway IPs
    if GATEWAY_IPS and ip in GATEWAY_IPS:
        return True
    
    # Fall back to internal IP check for development
    if not GATEWAY_IPS and is_internal_ip(ip):
        return True
    
    return False
