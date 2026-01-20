"""
SMSLY Shared Middleware Package

Provides common middleware for all microservices.
"""

from .gateway_guard import GatewayGuardMiddleware

__all__ = [
    "GatewayGuardMiddleware",
]
