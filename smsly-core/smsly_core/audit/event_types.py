"""
Audit Event Types
=================
Standard audit event types across all services.
"""

from enum import Enum


class AuditEventType(str, Enum):
    """Standard audit event types across all services."""
    # Authentication
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_FAILED = "auth.failed"
    AUTH_TOKEN_REFRESH = "auth.token_refresh"
    
    # API Keys
    APIKEY_CREATED = "apikey.created"
    APIKEY_ROTATED = "apikey.rotated"
    APIKEY_REVOKED = "apikey.revoked"
    APIKEY_USED = "apikey.used"
    
    # Messaging
    MESSAGE_SENT = "message.sent"
    MESSAGE_DELIVERED = "message.delivered"
    MESSAGE_FAILED = "message.failed"
    
    # Verification
    VERIFY_STARTED = "verify.started"
    VERIFY_COMPLETED = "verify.completed"
    VERIFY_FAILED = "verify.failed"
    
    # Campaigns
    CAMPAIGN_CREATED = "campaign.created"
    CAMPAIGN_STARTED = "campaign.started"
    CAMPAIGN_PAUSED = "campaign.paused"
    CAMPAIGN_COMPLETED = "campaign.completed"
    
    # Admin
    ADMIN_ACTION = "admin.action"
    CONFIG_CHANGED = "config.changed"
    USER_CREATED = "user.created"
    USER_MODIFIED = "user.modified"
    
    # Security
    SECURITY_BLOCK = "security.block"
    SECURITY_ALERT = "security.alert"
    RATE_LIMIT_HIT = "security.rate_limit"
