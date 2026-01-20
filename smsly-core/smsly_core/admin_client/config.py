"""
Admin Client Configuration
==========================
Configuration for admin backend connection.
"""

import os
from dataclasses import dataclass


@dataclass
class AdminConfig:
    """Configuration for admin backend connection."""
    base_url: str = os.environ.get(
        "ADMIN_BACKEND_URL", "http://localhost:8000"
    )
    staff_api_url: str = os.environ.get(
        "ADMIN_STAFF_API_URL", "http://localhost:8000/api/staff"
    )
    internal_secret: str = os.environ.get("INTERNAL_API_SECRET", "")
    timeout: float = 10.0
