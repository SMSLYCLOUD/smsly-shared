"""
IP Utility Functions
====================
Utilities for IP address checking and validation.
"""

import os
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
    
    # In environments without GATEWAY_IPS configured, do NOT fall back
    # to trusting all internal IPs — that creates a bypass vector where
    # any compromised container in the network can pose as the gateway.
    # Production deployments MUST explicitly set GATEWAY_IPS.
    if not GATEWAY_IPS:
        environment = os.getenv("ENVIRONMENT", "development")
        if environment in ("production", "staging", "prod"):
            # Hard fail: no GATEWAY_IPS in production = all internal traffic blocked
            return False
        # Development: allow all internal IPs as gateway
        if is_internal_ip(ip):
            return True
    
    return False
