"""
Service Adapters

Unified interface for all microservices with feature flag routing.
"""

from .base_adapter import BaseAdapter
from .sms_adapter import SMSAdapter, get_sms_adapter

__all__ = [
    'BaseAdapter',
    'SMSAdapter',
    'get_sms_adapter',
]
