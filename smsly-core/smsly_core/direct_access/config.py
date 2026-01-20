"""
Direct Access Protection Configuration
=======================================
Configuration constants and environment variables.
"""

import os
from typing import Set

# Configuration from environment
GATEWAY_IPS: Set[str] = set(
    os.getenv("GATEWAY_IPS", "").split(",")
) if os.getenv("GATEWAY_IPS") else set()

GATEWAY_URL = os.getenv("SECURITY_GATEWAY_URL", "https://gateway.smsly.io")
SERVICE_NAME = os.getenv("SERVICE_NAME", "smsly-microservice")
MAX_WARNINGS = int(os.getenv("DIRECT_ACCESS_MAX_WARNINGS", "2"))
BLACKLIST_DURATION_HOURS = int(os.getenv("BLACKLIST_DURATION_HOURS", "24"))

# Internal/allowed IPs that bypass protection (for health checks, etc.)
INTERNAL_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127."
)

# Default excluded paths (health checks, metrics)
DEFAULT_EXCLUDED_PATHS = {"/health", "/ready", "/metrics"}
