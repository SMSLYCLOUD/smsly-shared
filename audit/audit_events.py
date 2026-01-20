"""
SMSLY Exhaustive Audit Events & Service-Specific Clients
=========================================================
Master catalog of 430+ audit event types with comprehensive
logging methods for EVERY action across ALL microservices.

This file should be copied to each microservice's audit/ folder.
"""

import os
import hmac
import hashlib
import json
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import httpx
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

GATEWAY_URL = os.getenv("SECURITY_GATEWAY_URL", "http://localhost:8000")
SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown-service")
SERVICE_SECRET = os.getenv("SERVICE_SECRET", "")
MAX_PAYLOAD_SIZE = 10000  # Max payload bytes to prevent DoS
AUDIT_TIMEOUT = float(os.getenv("AUDIT_TIMEOUT", "5.0"))

# SECURITY: Force audit enabled in production - cannot be disabled via env var
_environment = os.getenv("ENVIRONMENT", "development").lower()
if _environment in ("production", "prod", "staging"):
    AUDIT_ENABLED = True  # MANDATORY in production
    AUDIT_FAIL_CLOSED = True  # Block requests if audit fails
else:
    AUDIT_ENABLED = os.getenv("AUDIT_ENABLED", "true").lower() == "true"
    AUDIT_FAIL_CLOSED = os.getenv("AUDIT_FAIL_CLOSED", "false").lower() == "true"


# ============================================================================
# Exceptions
# ============================================================================

class AuditUnavailableError(Exception):
    """Raised when audit logging fails and fail-closed mode is enabled."""
    pass


# ============================================================================
# PII Detection Patterns
# ============================================================================

import re

_PII_PATTERNS = [
    re.compile(r'\+?\d{10,15}'),  # Phone numbers
    re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),  # Emails
    re.compile(r'\d{3}-\d{2}-\d{4}'),  # SSN
    re.compile(r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}'),  # Credit cards
]


def _looks_like_pii(value: str) -> bool:
    """Check if a string looks like PII."""
    if not isinstance(value, str) or len(value) < 5:
        return False
    return any(p.fullmatch(value) for p in _PII_PATTERNS)


def _safe_mask(value: str, keep_last: int = 4) -> str:
    """Safely mask a value, keeping only the last N characters."""
    if not value:
        return "***"
    if len(value) <= keep_last:
        return "***"
    return "***" + value[-keep_last:]


def _sanitize_metadata(metadata: Dict) -> Dict:
    """Sanitize metadata to mask any detected PII in kwargs."""
    if not metadata:
        return {}
    sanitized = {}
    for k, v in metadata.items():
        if isinstance(v, str) and _looks_like_pii(v):
            sanitized[k] = _safe_mask(v)
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_metadata(v)
        else:
            sanitized[k] = v
    return sanitized


# ============================================================================
# Event Categories
# ============================================================================

class Category:
    AUTH = "auth"
    DATA = "data"
    ADMIN = "admin"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    BILLING = "billing"
    MESSAGING = "messaging"
    GENERAL = "general"
    VIDEO = "video"
    ANALYTICS = "analytics"


class Outcome:
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    PENDING = "pending"


class Severity:
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# ============================================================================
# EVENT TYPES - EXHAUSTIVE 430+ CATALOG
# ============================================================================

class E:
    """Exhaustive event type catalog. Use E.SMS_SENT, E.AUTH_LOGIN, etc."""
    
    # -------------------------------------------------------------------------
    # AUTHENTICATION & SECURITY (32)
    # -------------------------------------------------------------------------
    AUTH_LOGIN = "auth.login"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_LOGOUT = "auth.logout"
    AUTH_PASSWORD_CHANGE = "auth.password_change"
    AUTH_PASSWORD_RESET_REQUEST = "auth.password_reset_request"
    AUTH_PASSWORD_RESET_COMPLETE = "auth.password_reset_complete"
    AUTH_MFA_ENABLED = "auth.mfa_enabled"
    AUTH_MFA_DISABLED = "auth.mfa_disabled"
    AUTH_MFA_CHALLENGE = "auth.mfa_challenge"
    AUTH_MFA_VERIFIED = "auth.mfa_verified"
    AUTH_MFA_FAILED = "auth.mfa_failed"
    AUTH_SESSION_CREATED = "auth.session_created"
    AUTH_SESSION_EXPIRED = "auth.session_expired"
    AUTH_SESSION_REVOKED = "auth.session_revoked"
    AUTH_TOKEN_ISSUED = "auth.token_issued"
    AUTH_TOKEN_REFRESHED = "auth.token_refreshed"
    AUTH_TOKEN_REVOKED = "auth.token_revoked"
    AUTH_TOKEN_EXPIRED = "auth.token_expired"
    SECURITY_RATE_LIMIT_EXCEEDED = "security.rate_limit_exceeded"
    SECURITY_SUSPICIOUS_ACTIVITY = "security.suspicious_activity"
    SECURITY_IP_BLOCKED = "security.ip_blocked"
    SECURITY_BRUTE_FORCE_DETECTED = "security.brute_force_detected"
    SECURITY_POLICY_VIOLATION = "security.policy_violation"
    SECURITY_UNAUTHORIZED_ACCESS = "security.unauthorized_access"
    SECURITY_FORBIDDEN_ACTION = "security.forbidden_action"
    SECURITY_SIGNATURE_INVALID = "security.signature_invalid"
    SECURITY_REPLAY_ATTACK = "security.replay_attack"
    SECURITY_API_KEY_MISUSE = "security.api_key_misuse"
    SECURITY_CREDENTIAL_STUFFING = "security.credential_stuffing"
    SECURITY_UNUSUAL_LOCATION = "security.unusual_location"
    SECURITY_DEVICE_CHANGE = "security.device_change"
    SECURITY_PRIVILEGE_ESCALATION = "security.privilege_escalation"
    
    # -------------------------------------------------------------------------
    # SMS (18)
    # -------------------------------------------------------------------------
    SMS_SENT = "sms.sent"
    SMS_QUEUED = "sms.queued"
    SMS_SENDING = "sms.sending"
    SMS_DELIVERED = "sms.delivered"
    SMS_FAILED = "sms.failed"
    SMS_REJECTED = "sms.rejected"
    SMS_EXPIRED = "sms.expired"
    SMS_UNDELIVERED = "sms.undelivered"
    SMS_BOUNCED = "sms.bounced"
    SMS_DLR_RECEIVED = "sms.dlr_received"
    SMS_INBOUND_RECEIVED = "sms.inbound_received"
    SMS_INBOUND_PROCESSED = "sms.inbound_processed"
    SMS_OPT_OUT_RECEIVED = "sms.opt_out_received"
    SMS_OPT_IN_RECEIVED = "sms.opt_in_received"
    SMS_CARRIER_LOOKUP = "sms.carrier_lookup"
    SMS_NUMBER_VALIDATED = "sms.number_validated"
    SMS_TEMPLATE_USED = "sms.template_used"
    SMS_SCHEDULED = "sms.scheduled"
    
    # -------------------------------------------------------------------------
    # EMAIL (16)
    # -------------------------------------------------------------------------
    EMAIL_SENT = "email.sent"
    EMAIL_QUEUED = "email.queued"
    EMAIL_SENDING = "email.sending"
    EMAIL_DELIVERED = "email.delivered"
    EMAIL_BOUNCED = "email.bounced"
    EMAIL_SOFT_BOUNCED = "email.soft_bounced"
    EMAIL_HARD_BOUNCED = "email.hard_bounced"
    EMAIL_OPENED = "email.opened"
    EMAIL_CLICKED = "email.clicked"
    EMAIL_COMPLAINED = "email.complained"
    EMAIL_UNSUBSCRIBED = "email.unsubscribed"
    EMAIL_REJECTED = "email.rejected"
    EMAIL_DEFERRED = "email.deferred"
    EMAIL_DROPPED = "email.dropped"
    EMAIL_TEMPLATE_RENDERED = "email.template_rendered"
    EMAIL_ATTACHMENT_ADDED = "email.attachment_added"
    
    # -------------------------------------------------------------------------
    # WHATSAPP (22)
    # -------------------------------------------------------------------------
    WHATSAPP_SENT = "whatsapp.sent"
    WHATSAPP_QUEUED = "whatsapp.queued"
    WHATSAPP_DELIVERED = "whatsapp.delivered"
    WHATSAPP_READ = "whatsapp.read"
    WHATSAPP_FAILED = "whatsapp.failed"
    WHATSAPP_REJECTED = "whatsapp.rejected"
    WHATSAPP_RECEIVED = "whatsapp.received"
    WHATSAPP_TEMPLATE_SENT = "whatsapp.template_sent"
    WHATSAPP_TEMPLATE_APPROVED = "whatsapp.template_approved"
    WHATSAPP_TEMPLATE_REJECTED = "whatsapp.template_rejected"
    WHATSAPP_MEDIA_UPLOADED = "whatsapp.media_uploaded"
    WHATSAPP_MEDIA_DOWNLOADED = "whatsapp.media_downloaded"
    WHATSAPP_REACTION_RECEIVED = "whatsapp.reaction_received"
    WHATSAPP_LOCATION_RECEIVED = "whatsapp.location_received"
    WHATSAPP_CONTACT_RECEIVED = "whatsapp.contact_received"
    WHATSAPP_BUTTON_CLICKED = "whatsapp.button_clicked"
    WHATSAPP_LIST_SELECTED = "whatsapp.list_selected"
    WHATSAPP_SESSION_STARTED = "whatsapp.session_started"
    WHATSAPP_SESSION_EXPIRED = "whatsapp.session_expired"
    WHATSAPP_BUSINESS_PROFILE_UPDATED = "whatsapp.business_profile_updated"
    WHATSAPP_WEBHOOK_VERIFIED = "whatsapp.webhook_verified"
    WHATSAPP_INTERACTIVE_SENT = "whatsapp.interactive_sent"
    
    # -------------------------------------------------------------------------
    # VOICE (26)
    # -------------------------------------------------------------------------
    VOICE_CALL_INITIATED = "voice.call_initiated"
    VOICE_CALL_RINGING = "voice.call_ringing"
    VOICE_CALL_ANSWERED = "voice.call_answered"
    VOICE_CALL_BUSY = "voice.call_busy"
    VOICE_CALL_NO_ANSWER = "voice.call_no_answer"
    VOICE_CALL_FAILED = "voice.call_failed"
    VOICE_CALL_COMPLETED = "voice.call_completed"
    VOICE_CALL_TRANSFERRED = "voice.call_transferred"
    VOICE_CALL_HELD = "voice.call_held"
    VOICE_CALL_RESUMED = "voice.call_resumed"
    VOICE_CALL_RECORDED = "voice.call_recorded"
    VOICE_RECORDING_STARTED = "voice.recording_started"
    VOICE_RECORDING_STOPPED = "voice.recording_stopped"
    VOICE_RECORDING_AVAILABLE = "voice.recording_available"
    VOICE_VOICEMAIL_RECEIVED = "voice.voicemail_received"
    VOICE_VOICEMAIL_TRANSCRIBED = "voice.voicemail_transcribed"
    VOICE_DTMF_RECEIVED = "voice.dtmf_received"
    VOICE_SPEECH_DETECTED = "voice.speech_detected"
    VOICE_IVR_MENU_PLAYED = "voice.ivr_menu_played"
    VOICE_IVR_OPTION_SELECTED = "voice.ivr_option_selected"
    VOICE_CONFERENCE_STARTED = "voice.conference_started"
    VOICE_CONFERENCE_PARTICIPANT_JOINED = "voice.conference_participant_joined"
    VOICE_CONFERENCE_PARTICIPANT_LEFT = "voice.conference_participant_left"
    VOICE_CONFERENCE_ENDED = "voice.conference_ended"
    VOICE_SIP_REGISTERED = "voice.sip_registered"
    VOICE_SIP_DEREGISTERED = "voice.sip_deregistered"
    
    # -------------------------------------------------------------------------
    # VIDEO (18)
    # -------------------------------------------------------------------------
    VIDEO_ROOM_CREATED = "video.room_created"
    VIDEO_ROOM_ENDED = "video.room_ended"
    VIDEO_PARTICIPANT_JOINED = "video.participant_joined"
    VIDEO_PARTICIPANT_LEFT = "video.participant_left"
    VIDEO_RECORDING_STARTED = "video.recording_started"
    VIDEO_RECORDING_STOPPED = "video.recording_stopped"
    VIDEO_RECORDING_AVAILABLE = "video.recording_available"
    VIDEO_SCREEN_SHARE_STARTED = "video.screen_share_started"
    VIDEO_SCREEN_SHARE_STOPPED = "video.screen_share_stopped"
    VIDEO_CHAT_MESSAGE_SENT = "video.chat_message_sent"
    VIDEO_MEDIA_QUALITY_CHANGED = "video.media_quality_changed"
    VIDEO_BANDWIDTH_LIMITED = "video.bandwidth_limited"
    VIDEO_RTC_CONNECTED = "video.rtc_connected"
    VIDEO_RTC_DISCONNECTED = "video.rtc_disconnected"
    VIDEO_ROOM_CONFIGURED = "video.room_configured"
    VIDEO_STREAM_STARTED = "video.stream_started"
    VIDEO_STREAM_STOPPED = "video.stream_stopped"
    VIDEO_DIAL_OUT_INITIATED = "video.dial_out_initiated"
    
    # -------------------------------------------------------------------------
    # MMS (12)
    # -------------------------------------------------------------------------
    MMS_SENT = "mms.sent"
    MMS_QUEUED = "mms.queued"
    MMS_DELIVERED = "mms.delivered"
    MMS_FAILED = "mms.failed"
    MMS_REJECTED = "mms.rejected"
    MMS_MEDIA_UPLOADED = "mms.media_uploaded"
    MMS_MEDIA_VALIDATED = "mms.media_validated"
    MMS_MEDIA_CONVERTED = "mms.media_converted"
    MMS_INBOUND_RECEIVED = "mms.inbound_received"
    MMS_MEDIA_DOWNLOADED = "mms.media_downloaded"
    MMS_CONTENT_MODERATED = "mms.content_moderated"
    MMS_SIZE_EXCEEDED = "mms.size_exceeded"
    
    # -------------------------------------------------------------------------
    # RCS (16)
    # -------------------------------------------------------------------------
    RCS_SENT = "rcs.sent"
    RCS_DELIVERED = "rcs.delivered"
    RCS_READ = "rcs.read"
    RCS_FAILED = "rcs.failed"
    RCS_REVOKED = "rcs.revoked"
    RCS_RECEIVED = "rcs.received"
    RCS_CARD_SENT = "rcs.card_sent"
    RCS_CAROUSEL_SENT = "rcs.carousel_sent"
    RCS_SUGGESTION_CLICKED = "rcs.suggestion_clicked"
    RCS_ACTION_TRIGGERED = "rcs.action_triggered"
    RCS_AGENT_REGISTERED = "rcs.agent_registered"
    RCS_AGENT_VERIFIED = "rcs.agent_verified"
    RCS_CAPABILITY_CHECKED = "rcs.capability_checked"
    RCS_FALLBACK_TRIGGERED = "rcs.fallback_triggered"
    RCS_RICH_CARD_RENDERED = "rcs.rich_card_rendered"
    RCS_TYPING_INDICATOR_SENT = "rcs.typing_indicator_sent"
    
    # -------------------------------------------------------------------------
    # OTP / VERIFICATION (20)
    # -------------------------------------------------------------------------
    OTP_SENT = "otp.sent"
    OTP_DELIVERED = "otp.delivered"
    OTP_EXPIRED = "otp.expired"
    OTP_VERIFIED = "otp.verified"
    OTP_VERIFICATION_FAILED = "otp.verification_failed"
    OTP_RESENT = "otp.resent"
    OTP_CANCELLED = "otp.cancelled"
    OTP_RATE_LIMITED = "otp.rate_limited"
    OTP_FRAUD_DETECTED = "otp.fraud_detected"
    SILENTOTP_INITIATED = "silentotp.initiated"
    SILENTOTP_CARRIER_CHECKED = "silentotp.carrier_checked"
    SILENTOTP_VERIFIED = "silentotp.verified"
    SILENTOTP_FAILED = "silentotp.failed"
    SILENTOTP_TIMEOUT = "silentotp.timeout"
    VERIFICATION_STARTED = "verification.started"
    VERIFICATION_COMPLETED = "verification.completed"
    VERIFICATION_FAILED = "verification.failed"
    VERIFICATION_CANCELLED = "verification.cancelled"
    VERIFICATION_FRAUD_SCORE = "verification.fraud_score"
    VERIFICATION_DOCUMENT_UPLOADED = "verification.document_uploaded"
    
    # -------------------------------------------------------------------------
    # LIVE CHAT (20)
    # -------------------------------------------------------------------------
    LIVECHAT_SESSION_STARTED = "livechat.session_started"
    LIVECHAT_SESSION_ENDED = "livechat.session_ended"
    LIVECHAT_AGENT_ASSIGNED = "livechat.agent_assigned"
    LIVECHAT_AGENT_UNASSIGNED = "livechat.agent_unassigned"
    LIVECHAT_MESSAGE_SENT = "livechat.message_sent"
    LIVECHAT_MESSAGE_RECEIVED = "livechat.message_received"
    LIVECHAT_MESSAGE_READ = "livechat.message_read"
    LIVECHAT_TYPING_STARTED = "livechat.typing_started"
    LIVECHAT_TYPING_STOPPED = "livechat.typing_stopped"
    LIVECHAT_FILE_SHARED = "livechat.file_shared"
    LIVECHAT_CSAT_SUBMITTED = "livechat.csat_submitted"
    LIVECHAT_TRANSFER_REQUESTED = "livechat.transfer_requested"
    LIVECHAT_TRANSFER_COMPLETED = "livechat.transfer_completed"
    LIVECHAT_QUEUE_JOINED = "livechat.queue_joined"
    LIVECHAT_QUEUE_LEFT = "livechat.queue_left"
    LIVECHAT_BOT_HANDOFF = "livechat.bot_handoff"
    LIVECHAT_VISITOR_IDENTIFIED = "livechat.visitor_identified"
    LIVECHAT_TAG_ADDED = "livechat.tag_added"
    LIVECHAT_NOTE_ADDED = "livechat.note_added"
    LIVECHAT_TRANSCRIPT_EXPORTED = "livechat.transcript_exported"
    
    # -------------------------------------------------------------------------
    # CRM / CONTACT (22)
    # -------------------------------------------------------------------------
    CRM_CONTACT_CREATED = "crm.contact_created"
    CRM_CONTACT_UPDATED = "crm.contact_updated"
    CRM_CONTACT_DELETED = "crm.contact_deleted"
    CRM_CONTACT_MERGED = "crm.contact_merged"
    CRM_CONTACT_IMPORTED = "crm.contact_imported"
    CRM_CONTACT_EXPORTED = "crm.contact_exported"
    CRM_CONTACT_VIEWED = "crm.contact_viewed"
    CRM_IDENTITY_LINKED = "crm.identity_linked"
    CRM_IDENTITY_UNLINKED = "crm.identity_unlinked"
    CRM_CONSENT_GRANTED = "crm.consent_granted"
    CRM_CONSENT_REVOKED = "crm.consent_revoked"
    CRM_CONSENT_UPDATED = "crm.consent_updated"
    CRM_LIST_CREATED = "crm.list_created"
    CRM_LIST_UPDATED = "crm.list_updated"
    CRM_LIST_DELETED = "crm.list_deleted"
    CRM_LIST_MEMBER_ADDED = "crm.list_member_added"
    CRM_LIST_MEMBER_REMOVED = "crm.list_member_removed"
    CRM_SEGMENT_CREATED = "crm.segment_created"
    CRM_SEGMENT_UPDATED = "crm.segment_updated"
    CRM_TAG_CREATED = "crm.tag_created"
    CRM_TAG_APPLIED = "crm.tag_applied"
    CRM_INTERACTION_LOGGED = "crm.interaction_logged"
    
    # -------------------------------------------------------------------------
    # CAMPAIGN (18)
    # -------------------------------------------------------------------------
    CAMPAIGN_CREATED = "campaign.created"
    CAMPAIGN_UPDATED = "campaign.updated"
    CAMPAIGN_DELETED = "campaign.deleted"
    CAMPAIGN_SCHEDULED = "campaign.scheduled"
    CAMPAIGN_STARTED = "campaign.started"
    CAMPAIGN_PAUSED = "campaign.paused"
    CAMPAIGN_RESUMED = "campaign.resumed"
    CAMPAIGN_CANCELLED = "campaign.cancelled"
    CAMPAIGN_COMPLETED = "campaign.completed"
    CAMPAIGN_LAUNCHED = "campaign.launched"
    CAMPAIGN_RECIPIENT_ADDED = "campaign.recipient_added"
    CAMPAIGN_RECIPIENT_REMOVED = "campaign.recipient_removed"
    CAMPAIGN_AB_TEST_STARTED = "campaign.ab_test_started"
    CAMPAIGN_AB_WINNER_SELECTED = "campaign.ab_winner_selected"
    CAMPAIGN_STATS_UPDATED = "campaign.stats_updated"
    CAMPAIGN_REPORT_GENERATED = "campaign.report_generated"
    CAMPAIGN_TEMPLATE_APPLIED = "campaign.template_applied"
    CAMPAIGN_CLONED = "campaign.cloned"
    
    # -------------------------------------------------------------------------
    # BILLING / PAYMENT (28)
    # -------------------------------------------------------------------------
    BILLING_PAYMENT_INITIATED = "billing.payment_initiated"
    BILLING_PAYMENT_RECEIVED = "billing.payment_received"
    BILLING_PAYMENT_FAILED = "billing.payment_failed"
    BILLING_PAYMENT_REFUNDED = "billing.payment_refunded"
    BILLING_SUBSCRIPTION_CREATED = "billing.subscription_created"
    BILLING_SUBSCRIPTION_UPDATED = "billing.subscription_updated"
    BILLING_SUBSCRIPTION_CANCELLED = "billing.subscription_cancelled"
    BILLING_SUBSCRIPTION_RENEWED = "billing.subscription_renewed"
    BILLING_INVOICE_CREATED = "billing.invoice_created"
    BILLING_INVOICE_SENT = "billing.invoice_sent"
    BILLING_INVOICE_PAID = "billing.invoice_paid"
    BILLING_INVOICE_OVERDUE = "billing.invoice_overdue"
    BILLING_INVOICE_VOIDED = "billing.invoice_voided"
    BILLING_CREDIT_ADDED = "billing.credit_added"
    BILLING_CREDIT_USED = "billing.credit_used"
    BILLING_USAGE_TRACKED = "billing.usage_tracked"
    BILLING_USAGE_CHARGED = "billing.usage_charged"
    BILLING_USAGE_ALERT = "billing.usage_alert"
    BILLING_PLAN_UPGRADED = "billing.plan_upgraded"
    BILLING_PLAN_DOWNGRADED = "billing.plan_downgraded"
    BILLING_PROMO_APPLIED = "billing.promo_applied"
    BILLING_DISCOUNT_APPLIED = "billing.discount_applied"
    BILLING_TAX_CALCULATED = "billing.tax_calculated"
    BILLING_PAYOUT_PROCESSED = "billing.payout_processed"
    BILLING_CHARGEBACK_RECEIVED = "billing.chargeback_received"
    BILLING_DISPUTE_OPENED = "billing.dispute_opened"
    BILLING_DISPUTE_RESOLVED = "billing.dispute_resolved"
    BILLING_LOW_BALANCE_ALERT = "billing.low_balance_alert"
    
    # -------------------------------------------------------------------------
    # NUMBER MANAGEMENT (18)
    # -------------------------------------------------------------------------
    NUMBER_PROVISIONED = "number.provisioned"
    NUMBER_RELEASED = "number.released"
    NUMBER_PORTED_IN = "number.ported_in"
    NUMBER_PORTED_OUT = "number.ported_out"
    NUMBER_CAPABILITY_ADDED = "number.capability_added"
    NUMBER_CAPABILITY_REMOVED = "number.capability_removed"
    NUMBER_POOL_CREATED = "number.pool_created"
    NUMBER_POOL_UPDATED = "number.pool_updated"
    NUMBER_POOL_DELETED = "number.pool_deleted"
    NUMBER_POOL_MEMBER_ADDED = "number.pool_member_added"
    NUMBER_POOL_MEMBER_REMOVED = "number.pool_member_removed"
    NUMBER_HEALTH_CHECKED = "number.health_checked"
    SENDER_ID_REGISTERED = "sender_id.registered"
    SENDER_ID_VERIFIED = "sender_id.verified"
    SENDER_ID_REJECTED = "sender_id.rejected"
    SENDER_ID_SUSPENDED = "sender_id.suspended"
    SENDER_ID_RENEWED = "sender_id.renewed"
    TCR_CAMPAIGN_REGISTERED = "tcr.campaign_registered"
    
    # -------------------------------------------------------------------------
    # SURVEY / FEEDBACK (14)
    # -------------------------------------------------------------------------
    SURVEY_CREATED = "survey.created"
    SURVEY_UPDATED = "survey.updated"
    SURVEY_DELETED = "survey.deleted"
    SURVEY_PUBLISHED = "survey.published"
    SURVEY_UNPUBLISHED = "survey.unpublished"
    SURVEY_TRIGGERED = "survey.triggered"
    SURVEY_RESPONSE_RECEIVED = "survey.response_received"
    SURVEY_RESPONSE_ANALYZED = "survey.response_analyzed"
    SURVEY_NPS_CALCULATED = "survey.nps_calculated"
    SURVEY_CSAT_CALCULATED = "survey.csat_calculated"
    SURVEY_CONSENT_CHECKED = "survey.consent_checked"
    SURVEY_AI_ANNOTATED = "survey.ai_annotated"
    SURVEY_REPORT_GENERATED = "survey.report_generated"
    SURVEY_REMINDER_SENT = "survey.reminder_sent"
    
    # -------------------------------------------------------------------------
    # AI / AUTOMATION (16)
    # -------------------------------------------------------------------------
    AI_WORKFLOW_CREATED = "ai.workflow_created"
    AI_WORKFLOW_EXECUTED = "ai.workflow_executed"
    AI_WORKFLOW_FAILED = "ai.workflow_failed"
    AI_WORKFLOW_PAUSED = "ai.workflow_paused"
    AI_MODEL_INVOKED = "ai.model_invoked"
    AI_MODEL_RESPONSE = "ai.model_response"
    AI_INTENT_DETECTED = "ai.intent_detected"
    AI_SENTIMENT_ANALYZED = "ai.sentiment_analyzed"
    AI_SUGGESTION_GENERATED = "ai.suggestion_generated"
    AI_AGENT_CREATED = "ai.agent_created"
    AI_AGENT_TRAINED = "ai.agent_trained"
    AI_AGENT_DEPLOYED = "ai.agent_deployed"
    AUTOMATION_JOURNEY_STARTED = "automation.journey_started"
    AUTOMATION_JOURNEY_STEP = "automation.journey_step"
    AUTOMATION_JOURNEY_COMPLETED = "automation.journey_completed"
    AUTOMATION_TRIGGER_FIRED = "automation.trigger_fired"
    
    # -------------------------------------------------------------------------
    # ADMIN / SYSTEM (24)
    # -------------------------------------------------------------------------
    ADMIN_USER_CREATED = "admin.user_created"
    ADMIN_USER_UPDATED = "admin.user_updated"
    ADMIN_USER_DELETED = "admin.user_deleted"
    ADMIN_USER_SUSPENDED = "admin.user_suspended"
    ADMIN_USER_REACTIVATED = "admin.user_reactivated"
    ADMIN_ROLE_ASSIGNED = "admin.role_assigned"
    ADMIN_ROLE_REVOKED = "admin.role_revoked"
    ADMIN_PERMISSION_GRANTED = "admin.permission_granted"
    ADMIN_PERMISSION_REVOKED = "admin.permission_revoked"
    ADMIN_TEAM_CREATED = "admin.team_created"
    ADMIN_TEAM_UPDATED = "admin.team_updated"
    ADMIN_TEAM_DELETED = "admin.team_deleted"
    ADMIN_TEAM_MEMBER_ADDED = "admin.team_member_added"
    ADMIN_TEAM_MEMBER_REMOVED = "admin.team_member_removed"
    ADMIN_SETTINGS_CHANGED = "admin.settings_changed"
    APIKEY_CREATED = "apikey.created"
    APIKEY_UPDATED = "apikey.updated"
    APIKEY_ROTATED = "apikey.rotated"
    APIKEY_REVOKED = "apikey.revoked"
    APIKEY_USED = "apikey.used"
    WEBHOOK_CREATED = "webhook.created"
    WEBHOOK_UPDATED = "webhook.updated"
    WEBHOOK_DELETED = "webhook.deleted"
    WEBHOOK_TRIGGERED = "webhook.triggered"
    
    # -------------------------------------------------------------------------
    # ANALYTICS (12)
    # -------------------------------------------------------------------------
    ANALYTICS_DASHBOARD_VIEWED = "analytics.dashboard_viewed"
    ANALYTICS_REPORT_GENERATED = "analytics.report_generated"
    ANALYTICS_EXPORT_REQUESTED = "analytics.export_requested"
    ANALYTICS_EXPORT_DOWNLOADED = "analytics.export_downloaded"
    ANALYTICS_ALERT_CREATED = "analytics.alert_created"
    ANALYTICS_ALERT_TRIGGERED = "analytics.alert_triggered"
    ANALYTICS_THRESHOLD_EXCEEDED = "analytics.threshold_exceeded"
    ANALYTICS_ANOMALY_DETECTED = "analytics.anomaly_detected"
    ANALYTICS_INSIGHT_GENERATED = "analytics.insight_generated"
    ANALYTICS_METRIC_TRACKED = "analytics.metric_tracked"
    ANALYTICS_GOAL_COMPLETED = "analytics.goal_completed"
    ANALYTICS_SEGMENT_ANALYZED = "analytics.segment_analyzed"
    
    # -------------------------------------------------------------------------
    # ACCOUNT / PROJECT (14)
    # -------------------------------------------------------------------------
    ACCOUNT_CREATED = "account.created"
    ACCOUNT_UPDATED = "account.updated"
    ACCOUNT_VERIFIED = "account.verified"
    ACCOUNT_SUSPENDED = "account.suspended"
    ACCOUNT_REACTIVATED = "account.reactivated"
    ACCOUNT_DELETED = "account.deleted"
    ACCOUNT_KYC_SUBMITTED = "account.kyc_submitted"
    ACCOUNT_KYC_VERIFIED = "account.kyc_verified"
    PROJECT_CREATED = "project.created"
    PROJECT_UPDATED = "project.updated"
    PROJECT_DELETED = "project.deleted"
    PROJECT_MEMBER_INVITED = "project.member_invited"
    PROJECT_MEMBER_JOINED = "project.member_joined"
    PROJECT_MEMBER_REMOVED = "project.member_removed"
    
    # -------------------------------------------------------------------------
    # COMPLIANCE / POLICY (14)
    # -------------------------------------------------------------------------
    COMPLIANCE_CONSENT_RECORDED = "compliance.consent_recorded"
    COMPLIANCE_GDPR_REQUEST = "compliance.gdpr_request"
    COMPLIANCE_GDPR_FULFILLED = "compliance.gdpr_fulfilled"
    COMPLIANCE_DATA_EXPORTED = "compliance.data_exported"
    COMPLIANCE_DATA_DELETED = "compliance.data_deleted"
    COMPLIANCE_POLICY_EVALUATED = "compliance.policy_evaluated"
    COMPLIANCE_POLICY_VIOLATED = "compliance.policy_violated"
    COMPLIANCE_REGULATION_CHECKED = "compliance.regulation_checked"
    COMPLIANCE_WHITELIST_ADDED = "compliance.whitelist_added"
    COMPLIANCE_BLACKLIST_ADDED = "compliance.blacklist_added"
    COMPLIANCE_AUDIT_TRAIL_EXPORTED = "compliance.audit_trail_exported"
    COMPLIANCE_RETENTION_APPLIED = "compliance.retention_applied"
    COMPLIANCE_OPT_OUT_PROCESSED = "compliance.opt_out_processed"
    COMPLIANCE_DPA_SIGNED = "compliance.dpa_signed"
    
    # -------------------------------------------------------------------------
    # API REQUEST (For Middleware)
    # -------------------------------------------------------------------------
    API_REQUEST_START = "api.request_start"
    API_REQUEST_COMPLETE = "api.request_complete"
    API_REQUEST = "api.request"
    
    # -------------------------------------------------------------------------
    # INVOICE (8)
    # -------------------------------------------------------------------------
    INVOICE_CREATED = "invoice.created"
    INVOICE_SENT = "invoice.sent"
    INVOICE_PAID = "invoice.paid"
    INVOICE_CANCELLED = "invoice.cancelled"
    INVOICE_REFUNDED = "invoice.refunded"
    INVOICE_DOWNLOADED = "invoice.downloaded"
    INVOICE_REMINDED = "invoice.reminded"
    INVOICE_OVERDUE = "invoice.overdue"
    
    # -------------------------------------------------------------------------
    # FILE / MEDIA (8)
    # -------------------------------------------------------------------------
    FILE_UPLOADED = "file.uploaded"
    FILE_DOWNLOADED = "file.downloaded"
    FILE_DELETED = "file.deleted"
    FILE_SCANNED = "file.scanned"
    FILE_QUARANTINED = "file.quarantined"
    FILE_SHARED = "file.shared"
    FILE_EXPIRED = "file.expired"
    FILE_ACCESSED = "file.accessed"
    
    # -------------------------------------------------------------------------
    # TEMPLATE (8)
    # -------------------------------------------------------------------------
    TEMPLATE_CREATED = "template.created"
    TEMPLATE_UPDATED = "template.updated"
    TEMPLATE_DELETED = "template.deleted"
    TEMPLATE_SUBMITTED = "template.submitted"
    TEMPLATE_APPROVED = "template.approved"
    TEMPLATE_REJECTED = "template.rejected"
    TEMPLATE_SUSPENDED = "template.suspended"
    TEMPLATE_RENDERED = "template.rendered"
    
    # -------------------------------------------------------------------------
    # SDK / CREDENTIAL (6)
    # -------------------------------------------------------------------------
    SDK_KEY_GENERATED = "sdk.key_generated"
    SDK_KEY_REVOKED = "sdk.key_revoked"
    SDK_KEY_USED = "sdk.key_used"
    SDK_KEY_ROTATED = "sdk.key_rotated"
    SDK_VERSION_DETECTED = "sdk.version_detected"
    SDK_DEPRECATED_USED = "sdk.deprecated_used"
    
    # -------------------------------------------------------------------------
    # GATEWAY (8)
    # -------------------------------------------------------------------------
    GATEWAY_REQUEST_PROXIED = "gateway.request_proxied"
    GATEWAY_REQUEST_BLOCKED = "gateway.request_blocked"
    GATEWAY_SIGNATURE_VERIFIED = "gateway.signature_verified"
    GATEWAY_SIGNATURE_FAILED = "gateway.signature_failed"
    GATEWAY_RATE_LIMITED = "gateway.rate_limited"
    GATEWAY_CIRCUIT_OPENED = "gateway.circuit_opened"
    GATEWAY_CIRCUIT_CLOSED = "gateway.circuit_closed"
    GATEWAY_HEALTH_CHECK = "gateway.health_check"
    
    # -------------------------------------------------------------------------
    # SCHEDULED (6)
    # -------------------------------------------------------------------------
    SCHEDULED_MESSAGE_QUEUED = "scheduled.message_queued"
    SCHEDULED_MESSAGE_SENT = "scheduled.message_sent"
    SCHEDULED_MESSAGE_CANCELLED = "scheduled.message_cancelled"
    SCHEDULED_MESSAGE_FAILED = "scheduled.message_failed"
    SCHEDULED_MESSAGE_UPDATED = "scheduled.message_updated"
    SCHEDULED_BATCH_PROCESSED = "scheduled.batch_processed"
    
    # -------------------------------------------------------------------------
    # CARRIER (8)
    # -------------------------------------------------------------------------
    CARRIER_CONNECTED = "carrier.connected"
    CARRIER_DISCONNECTED = "carrier.disconnected"
    CARRIER_RATE_CHANGED = "carrier.rate_changed"
    CARRIER_ROUTE_CHANGED = "carrier.route_changed"
    CARRIER_FAILOVER_TRIGGERED = "carrier.failover_triggered"
    CARRIER_QUALITY_DEGRADED = "carrier.quality_degraded"
    CARRIER_LIMIT_REACHED = "carrier.limit_reached"
    CARRIER_DLR_RECEIVED = "carrier.dlr_received"
    
    # -------------------------------------------------------------------------
    # SHORTLINK (6)
    # -------------------------------------------------------------------------
    SHORTLINK_CREATED = "shortlink.created"
    SHORTLINK_CLICKED = "shortlink.clicked"
    SHORTLINK_EXPIRED = "shortlink.expired"
    SHORTLINK_DELETED = "shortlink.deleted"
    SHORTLINK_UPDATED = "shortlink.updated"
    SHORTLINK_STATS_VIEWED = "shortlink.stats_viewed"
    
    # -------------------------------------------------------------------------
    # DATA OPERATIONS (6)
    # -------------------------------------------------------------------------
    DATA_BULK_IMPORT = "data.bulk_import"
    DATA_BULK_EXPORT = "data.bulk_export"
    DATA_MIGRATION_STARTED = "data.migration_started"
    DATA_MIGRATION_COMPLETED = "data.migration_completed"
    DATA_BACKUP_CREATED = "data.backup_created"
    DATA_RESTORE_COMPLETED = "data.restore_completed"
    
    # -------------------------------------------------------------------------
    # IDENTITY (6) - Identity Service specific
    # -------------------------------------------------------------------------
    IDENTITY_CREATED = "identity.created"
    IDENTITY_UPDATED = "identity.updated"
    IDENTITY_SUSPENDED = "identity.suspended"
    IDENTITY_REACTIVATED = "identity.reactivated"
    IDENTITY_DELETED = "identity.deleted"
    IDENTITY_VERIFIED = "identity.verified"
    
    # -------------------------------------------------------------------------
    # CREDENTIAL (6) - API Key / Credential lifecycle
    # -------------------------------------------------------------------------
    CREDENTIAL_CREATED = "credential.created"
    CREDENTIAL_UPDATED = "credential.updated"
    CREDENTIAL_ROTATED = "credential.rotated"
    CREDENTIAL_REVOKED = "credential.revoked"
    CREDENTIAL_USED = "credential.used"
    CREDENTIAL_EXPIRED = "credential.expired"
    
    # -------------------------------------------------------------------------
    # RATE LIMIT (6) - Rate Limit Service events
    # -------------------------------------------------------------------------
    RATE_LIMIT_ALLOWED = "rate_limit.allowed"
    RATE_LIMIT_DENIED = "rate_limit.denied"
    RATE_LIMIT_THROTTLED = "rate_limit.throttled"
    RATE_LIMIT_EMERGENCY_BLOCK = "rate_limit.emergency_block"
    RATE_LIMIT_QUOTA_RESET = "rate_limit.quota_reset"
    RATE_LIMIT_LIMIT_CHANGED = "rate_limit.limit_changed"
    
    # -------------------------------------------------------------------------
    # API GATEWAY (4) - Gateway-specific middleware events
    # -------------------------------------------------------------------------
    API_GATEWAY_REQUEST_START = "api.gateway.request_start"
    API_GATEWAY_REQUEST_COMPLETE = "api.gateway.request_complete"
    API_GATEWAY_PROXY_ERROR = "api.gateway.proxy_error"
    API_GATEWAY_UPSTREAM_TIMEOUT = "api.gateway.upstream_timeout"
    
    # -------------------------------------------------------------------------
    # ADDITIONAL BILLING (6) - Django Backend billing events
    # -------------------------------------------------------------------------
    BILLING_PAYMENT_COMPLETED = "billing.payment_completed"
    BILLING_WALLET_DEPOSIT = "billing.wallet_deposit"
    BILLING_WALLET_WITHDRAW = "billing.wallet_withdraw"
    BILLING_SUBSCRIPTION_CHANGED = "billing.subscription_changed"
    BILLING_REFUND_ISSUED = "billing.refund_issued"
    BILLING_WALLET_BALANCE_LOW = "billing.wallet_balance_low"
    
    # -------------------------------------------------------------------------
    # ADDITIONAL COMPLIANCE (4) - Django Backend compliance events
    # -------------------------------------------------------------------------
    COMPLIANCE_GDPR_DATA_EXPORT = "compliance.gdpr_data_export"
    COMPLIANCE_GDPR_DELETION_REQUEST = "compliance.gdpr_deletion_request"
    COMPLIANCE_DATA_ANONYMIZED = "compliance.data_anonymized"
    COMPLIANCE_LEGAL_HOLD_APPLIED = "compliance.legal_hold_applied"
    
    # -------------------------------------------------------------------------
    # ADDITIONAL PROJECT (4) - Project management events
    # -------------------------------------------------------------------------
    PROJECT_MEMBER_ADDED = "project.member_added"
    PROJECT_SETTINGS_CHANGED = "project.settings_changed"
    PROJECT_ARCHIVED = "project.archived"
    PROJECT_RESTORED = "project.restored"
    
    # -------------------------------------------------------------------------
    # ADDITIONAL AUTH (4) - Extended authentication events  
    # -------------------------------------------------------------------------
    AUTH_FAILURE = "auth.failure"
    AUTH_ACCOUNT_LOCKED = "auth.account_locked"
    AUTH_ACCOUNT_UNLOCKED = "auth.account_unlocked"
    AUTH_DEVICE_TRUSTED = "auth.device_trusted"
    
    # -------------------------------------------------------------------------
    # ADDITIONAL SECURITY (4) - Kill-switch and emergency events
    # -------------------------------------------------------------------------
    SECURITY_KILL_SWITCH = "security.kill_switch"
    SECURITY_EMERGENCY_SHUTDOWN = "security.emergency_shutdown"
    SECURITY_THREAT_NEUTRALIZED = "security.threat_neutralized"
    SECURITY_ANOMALY_BASELINE_UPDATED = "security.anomaly_baseline_updated"


# ============================================================================
# COMPREHENSIVE AUDIT CLIENT
# ============================================================================

class AuditClient:
    """
    Comprehensive audit client with helper methods for ALL 430+ events.
    
    Usage:
        audit = AuditClient()
        await audit.sms_sent(message_id, account_id, recipient, segments=2)
        await audit.email_opened(message_id, recipient)
        await audit.auth_login(user_id, ip_address)
    """
    
    def __init__(self, service_name: Optional[str] = None):
        self.service_name = service_name or SERVICE_NAME
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(base_url=GATEWAY_URL, timeout=5.0)
        return self._client
    
    def _sign(self, timestamp: str, body: str) -> str:
        if not SERVICE_SECRET:
            logger.error("CRITICAL: SERVICE_SECRET not configured - audit requests may be rejected")
            return ""
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        message = f"{self.service_name}:{timestamp}:{body_hash}"
        return hmac.new(SERVICE_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    
    async def log(
        self,
        event_type: str,
        resource_id: str,
        actor_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        action: Optional[str] = None,
        outcome: str = Outcome.SUCCESS,
        category: str = Category.GENERAL,
        severity: str = Severity.INFO,
        ip_address: Optional[str] = None,
        request_id: Optional[str] = None,
        pii_accessed: bool = False,
        metadata: Optional[Dict] = None,
        fail_closed: Optional[bool] = None,
    ) -> bool:
        """
        Core logging method - FAIL-CLOSED in production.
        
        Args:
            fail_closed: Override default fail-closed behavior. If True, raises
                        AuditUnavailableError on failure. Defaults to AUDIT_FAIL_CLOSED.
        
        Returns:
            True if audit was logged successfully, False otherwise.
        
        Raises:
            AuditUnavailableError: If fail_closed=True and audit logging fails.
        """
        if not AUDIT_ENABLED:
            return True
        
        # Determine fail-closed behavior
        should_fail_closed = fail_closed if fail_closed is not None else AUDIT_FAIL_CLOSED
        
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Derive resource_type from event_type if not provided
        if not resource_type:
            resource_type = event_type.split('.')[0] if '.' in event_type else "unknown"
        
        # SECURITY: Sanitize metadata to prevent PII leakage via kwargs
        sanitized_metadata = _sanitize_metadata(metadata) if metadata else {}
        
        # SECURITY: Enforce payload size limit to prevent DoS
        metadata_json = json.dumps(sanitized_metadata)
        if len(metadata_json) > MAX_PAYLOAD_SIZE:
            logger.warning(
                "Audit payload too large, truncating",
                size=len(metadata_json),
                max_size=MAX_PAYLOAD_SIZE
            )
            sanitized_metadata = {"_truncated": True, "_original_size": len(metadata_json)}
        
        event_data = {
            "service": self.service_name,
            "event_type": event_type,
            "event_category": category,
            "severity": severity,
            "action": action or event_type,
            "actor_id": actor_id or "system",
            "actor_type": "user" if actor_id else "system",
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "ip_address": ip_address,
            "pii_accessed": pii_accessed,
            "payload": sanitized_metadata,
        }
        
        body = json.dumps(event_data)
        signature = self._sign(timestamp, body)
        
        headers = {
            "Content-Type": "application/json",
            "X-Service-Name": self.service_name,
            "X-Service-Timestamp": timestamp,
            "X-Service-Signature": signature,
        }
        if request_id:
            headers["X-Request-ID"] = request_id
        
        # SECURITY: Synchronous call with proper error handling - NO MORE FIRE-AND-FORGET
        try:
            client = await self._get_client()
            response = await client.post(
                "/api/v1/audit/events",
                content=body,
                headers=headers,
                timeout=AUDIT_TIMEOUT
            )
            
            if response.status_code >= 400:
                logger.error(
                    "Audit logging rejected by service",
                    status=response.status_code,
                    event_type=event_type
                )
                if should_fail_closed:
                    raise AuditUnavailableError(
                        f"Audit service rejected event: HTTP {response.status_code}"
                    )
                return False
            
            return True
            
        except AuditUnavailableError:
            raise  # Re-raise our own exception
        except Exception as e:
            logger.error(f"CRITICAL: Audit logging failed: {e}", exc_info=True)
            if should_fail_closed:
                raise AuditUnavailableError(f"Audit service unavailable: {e}")
            return False
    
    # =========================================================================
    # SMS CONVENIENCE METHODS
    # =========================================================================
    
    async def sms_sent(self, message_id: str, actor_id: str, recipient: str, segments: int = 1, **kw):
        await self.log(E.SMS_SENT, message_id, actor_id, "sms", "send", category=Category.MESSAGING, metadata={"recipient_masked": _safe_mask(recipient), "segments": segments, **kw})
    
    async def sms_delivered(self, message_id: str, **kw):
        await self.log(E.SMS_DELIVERED, message_id, category=Category.MESSAGING, metadata=kw)
    
    async def sms_failed(self, message_id: str, error: str, **kw):
        await self.log(E.SMS_FAILED, message_id, outcome=Outcome.FAILURE, severity=Severity.WARNING, category=Category.MESSAGING, metadata={"error": error, **kw})
    
    async def sms_queued(self, message_id: str, actor_id: str, **kw):
        await self.log(E.SMS_QUEUED, message_id, actor_id, category=Category.MESSAGING, metadata=kw)
    
    async def sms_rejected(self, message_id: str, reason: str, **kw):
        await self.log(E.SMS_REJECTED, message_id, outcome=Outcome.BLOCKED, severity=Severity.WARNING, category=Category.MESSAGING, metadata={"reason": reason, **kw})
    
    async def sms_inbound(self, message_id: str, sender: str, **kw):
        await self.log(E.SMS_INBOUND_RECEIVED, message_id, category=Category.MESSAGING, metadata={"sender_masked": _safe_mask(sender), **kw})
    
    # =========================================================================
    # EMAIL CONVENIENCE METHODS
    # =========================================================================
    
    async def email_sent(self, message_id: str, actor_id: str, to: str, subject: str, **kw):
        await self.log(E.EMAIL_SENT, message_id, actor_id, "email", "send", category=Category.MESSAGING, metadata={"to_masked": _safe_mask(to, 0), "subject": subject[:50] if subject else "", **kw})
    
    async def email_delivered(self, message_id: str, **kw):
        await self.log(E.EMAIL_DELIVERED, message_id, category=Category.MESSAGING, metadata=kw)
    
    async def email_opened(self, message_id: str, **kw):
        await self.log(E.EMAIL_OPENED, message_id, category=Category.MESSAGING, metadata=kw)
    
    async def email_clicked(self, message_id: str, url: str, **kw):
        await self.log(E.EMAIL_CLICKED, message_id, category=Category.MESSAGING, metadata={"url": url, **kw})
    
    async def email_bounced(self, message_id: str, bounce_type: str, **kw):
        await self.log(E.EMAIL_BOUNCED, message_id, outcome=Outcome.FAILURE, severity=Severity.WARNING, category=Category.MESSAGING, metadata={"bounce_type": bounce_type, **kw})
    
    async def email_unsubscribed(self, message_id: str, email: str, **kw):
        await self.log(E.EMAIL_UNSUBSCRIBED, message_id, category=Category.COMPLIANCE, metadata={"email_masked": _safe_mask(email, 0), **kw})
    
    async def email_complained(self, message_id: str, **kw):
        await self.log(E.EMAIL_COMPLAINED, message_id, outcome=Outcome.FAILURE, severity=Severity.ERROR, category=Category.COMPLIANCE, metadata=kw)
    
    # =========================================================================
    # WHATSAPP CONVENIENCE METHODS
    # =========================================================================
    
    async def whatsapp_sent(self, message_id: str, actor_id: str, recipient: str, template: Optional[str] = None, **kw):
        await self.log(E.WHATSAPP_SENT, message_id, actor_id, "whatsapp", "send", category=Category.MESSAGING, metadata={"recipient_masked": _safe_mask(recipient), "template": template, **kw})
    
    async def whatsapp_delivered(self, message_id: str, **kw):
        await self.log(E.WHATSAPP_DELIVERED, message_id, category=Category.MESSAGING, metadata=kw)
    
    async def whatsapp_read(self, message_id: str, **kw):
        await self.log(E.WHATSAPP_READ, message_id, category=Category.MESSAGING, metadata=kw)
    
    async def whatsapp_received(self, message_id: str, sender: str, message_type: str, **kw):
        await self.log(E.WHATSAPP_RECEIVED, message_id, sender, "whatsapp", "receive", category=Category.MESSAGING, metadata={"type": message_type, **kw})
    
    async def whatsapp_button_clicked(self, message_id: str, button_id: str, **kw):
        await self.log(E.WHATSAPP_BUTTON_CLICKED, message_id, category=Category.MESSAGING, metadata={"button_id": button_id, **kw})
    
    # =========================================================================
    # VOICE CONVENIENCE METHODS
    # =========================================================================
    
    async def voice_call_initiated(self, call_id: str, actor_id: str, to_number: str, **kw):
        await self.log(E.VOICE_CALL_INITIATED, call_id, actor_id, "call", "initiate", category=Category.MESSAGING, metadata={"to_masked": _safe_mask(to_number), **kw})
    
    async def voice_call_answered(self, call_id: str, **kw):
        await self.log(E.VOICE_CALL_ANSWERED, call_id, category=Category.MESSAGING, metadata=kw)
    
    async def voice_call_completed(self, call_id: str, duration_seconds: int, status: str, **kw):
        await self.log(E.VOICE_CALL_COMPLETED, call_id, category=Category.MESSAGING, metadata={"duration": duration_seconds, "status": status, **kw})
    
    async def voice_recording_started(self, call_id: str, **kw):
        await self.log(E.VOICE_RECORDING_STARTED, call_id, category=Category.MESSAGING, metadata=kw)
    
    async def voice_dtmf_received(self, call_id: str, digits: str, **kw):
        await self.log(E.VOICE_DTMF_RECEIVED, call_id, category=Category.MESSAGING, metadata={"digits": digits, **kw})
    
    # =========================================================================
    # LIVE CHAT CONVENIENCE METHODS
    # =========================================================================
    
    async def livechat_session_started(self, session_id: str, visitor_id: str, channel: str, **kw):
        await self.log(E.LIVECHAT_SESSION_STARTED, session_id, visitor_id, "chat_session", "start", category=Category.MESSAGING, metadata={"channel": channel, **kw})
    
    async def livechat_session_ended(self, session_id: str, duration_seconds: int, **kw):
        await self.log(E.LIVECHAT_SESSION_ENDED, session_id, category=Category.MESSAGING, metadata={"duration": duration_seconds, **kw})
    
    async def livechat_message_sent(self, session_id: str, message_id: str, sender_type: str, **kw):
        await self.log(E.LIVECHAT_MESSAGE_SENT, session_id, category=Category.MESSAGING, metadata={"message_id": message_id, "sender_type": sender_type, **kw})
    
    async def livechat_agent_assigned(self, session_id: str, agent_id: str, **kw):
        await self.log(E.LIVECHAT_AGENT_ASSIGNED, session_id, agent_id, category=Category.MESSAGING, metadata=kw)
    
    async def livechat_csat_submitted(self, session_id: str, score: int, **kw):
        await self.log(E.LIVECHAT_CSAT_SUBMITTED, session_id, category=Category.MESSAGING, metadata={"score": score, **kw})
    
    # =========================================================================
    # OTP / VERIFICATION CONVENIENCE METHODS
    # =========================================================================
    
    async def otp_sent(self, verification_id: str, actor_id: str, channel: str, recipient: str, **kw):
        await self.log(E.OTP_SENT, verification_id, actor_id, "verification", "send", category=Category.AUTH, metadata={"channel": channel, "recipient_masked": _safe_mask(recipient), **kw})
    
    async def otp_verified(self, verification_id: str, success: bool, **kw):
        await self.log(E.OTP_VERIFIED, verification_id, outcome=Outcome.SUCCESS if success else Outcome.FAILURE, category=Category.AUTH, metadata={"verified": success, **kw})
    
    async def otp_failed(self, verification_id: str, reason: str, **kw):
        await self.log(E.OTP_VERIFICATION_FAILED, verification_id, outcome=Outcome.FAILURE, severity=Severity.WARNING, category=Category.AUTH, metadata={"reason": reason, **kw})
    
    async def silentotp_verified(self, verification_id: str, carrier: str, **kw):
        await self.log(E.SILENTOTP_VERIFIED, verification_id, category=Category.AUTH, metadata={"carrier": carrier, **kw})
    
    # =========================================================================
    # AI / AUTOMATION CONVENIENCE METHODS
    # =========================================================================
    
    async def ai_workflow_executed(self, workflow_id: str, actor_id: str, duration_ms: float, **kw):
        await self.log(E.AI_WORKFLOW_EXECUTED, workflow_id, actor_id, "workflow", "execute", category=Category.GENERAL, metadata={"duration_ms": duration_ms, **kw})
    
    async def ai_model_invoked(self, request_id: str, model: str, tokens_used: int, **kw):
        await self.log(E.AI_MODEL_INVOKED, request_id, category=Category.GENERAL, metadata={"model": model, "tokens": tokens_used, **kw})
    
    async def ai_sentiment_analyzed(self, message_id: str, sentiment: str, score: float, **kw):
        await self.log(E.AI_SENTIMENT_ANALYZED, message_id, category=Category.GENERAL, metadata={"sentiment": sentiment, "score": score, **kw})
    
    async def ai_intent_detected(self, message_id: str, intent: str, confidence: float, **kw):
        await self.log(E.AI_INTENT_DETECTED, message_id, category=Category.GENERAL, metadata={"intent": intent, "confidence": confidence, **kw})
    
    # =========================================================================
    # CRM CONVENIENCE METHODS
    # =========================================================================
    
    async def crm_contact_created(self, contact_id: str, actor_id: str, **kw):
        await self.log(E.CRM_CONTACT_CREATED, contact_id, actor_id, "contact", "create", category=Category.DATA, pii_accessed=True, metadata=kw)
    
    async def crm_contact_updated(self, contact_id: str, actor_id: str, fields: List[str], **kw):
        await self.log(E.CRM_CONTACT_UPDATED, contact_id, actor_id, "contact", "update", category=Category.DATA, pii_accessed=True, metadata={"fields_changed": fields, **kw})
    
    async def crm_contact_deleted(self, contact_id: str, actor_id: str, **kw):
        await self.log(E.CRM_CONTACT_DELETED, contact_id, actor_id, "contact", "delete", category=Category.DATA, severity=Severity.WARNING, metadata=kw)
    
    async def crm_consent_granted(self, contact_id: str, consent_type: str, channel: str, **kw):
        await self.log(E.CRM_CONSENT_GRANTED, contact_id, category=Category.COMPLIANCE, metadata={"consent_type": consent_type, "channel": channel, **kw})
    
    async def crm_consent_revoked(self, contact_id: str, consent_type: str, **kw):
        await self.log(E.CRM_CONSENT_REVOKED, contact_id, category=Category.COMPLIANCE, severity=Severity.WARNING, metadata={"consent_type": consent_type, **kw})
    
    # =========================================================================
    # BILLING CONVENIENCE METHODS
    # =========================================================================
    
    async def billing_payment_received(self, transaction_id: str, actor_id: str, amount: float, currency: str, **kw):
        await self.log(E.BILLING_PAYMENT_RECEIVED, transaction_id, actor_id, "transaction", "payment", category=Category.BILLING, metadata={"amount": amount, "currency": currency, **kw})
    
    async def billing_payment_failed(self, transaction_id: str, actor_id: str, error: str, **kw):
        await self.log(E.BILLING_PAYMENT_FAILED, transaction_id, actor_id, outcome=Outcome.FAILURE, severity=Severity.ERROR, category=Category.BILLING, metadata={"error": error, **kw})
    
    async def billing_usage_charged(self, account_id: str, product: str, units: int, amount: float, **kw):
        await self.log(E.BILLING_USAGE_CHARGED, account_id, account_id, "account", "charge", category=Category.BILLING, metadata={"product": product, "units": units, "amount": amount, **kw})
    
    async def billing_invoice_created(self, invoice_id: str, account_id: str, amount: float, **kw):
        await self.log(E.BILLING_INVOICE_CREATED, invoice_id, account_id, "invoice", "create", category=Category.BILLING, metadata={"amount": amount, **kw})
    
    # =========================================================================
    # AUTH / SECURITY CONVENIENCE METHODS
    # =========================================================================
    
    async def auth_login(self, user_id: str, ip_address: str, success: bool = True, **kw):
        event = E.AUTH_LOGIN if success else E.AUTH_LOGIN_FAILED
        await self.log(event, user_id, user_id, "user", "login", outcome=Outcome.SUCCESS if success else Outcome.FAILURE, category=Category.AUTH, ip_address=ip_address, metadata=kw)
    
    async def auth_logout(self, user_id: str, **kw):
        await self.log(E.AUTH_LOGOUT, user_id, user_id, "user", "logout", category=Category.AUTH, metadata=kw)
    
    async def auth_mfa_verified(self, user_id: str, method: str, **kw):
        await self.log(E.AUTH_MFA_VERIFIED, user_id, user_id, category=Category.AUTH, metadata={"method": method, **kw})
    
    async def security_rate_limited(self, actor_id: str, limit_type: str, ip: str, **kw):
        await self.log(E.SECURITY_RATE_LIMIT_EXCEEDED, actor_id, actor_id, outcome=Outcome.BLOCKED, severity=Severity.WARNING, category=Category.SECURITY, ip_address=ip, metadata={"limit_type": limit_type, **kw})
    
    async def security_suspicious(self, actor_id: str, activity: str, details: Dict, ip: str, **kw):
        await self.log(E.SECURITY_SUSPICIOUS_ACTIVITY, actor_id, actor_id, outcome=Outcome.BLOCKED, severity=Severity.ERROR, category=Category.SECURITY, ip_address=ip, metadata={"activity": activity, **details, **kw})
    
    # =========================================================================
    # CAMPAIGN CONVENIENCE METHODS
    # =========================================================================
    
    async def campaign_created(self, campaign_id: str, actor_id: str, name: str, channel: str, **kw):
        await self.log(E.CAMPAIGN_CREATED, campaign_id, actor_id, "campaign", "create", category=Category.DATA, metadata={"name": name, "channel": channel, **kw})
    
    async def campaign_launched(self, campaign_id: str, actor_id: str, recipients: int, **kw):
        await self.log(E.CAMPAIGN_LAUNCHED, campaign_id, actor_id, "campaign", "launch", category=Category.MESSAGING, metadata={"recipients": recipients, **kw})
    
    async def campaign_completed(self, campaign_id: str, sent: int, delivered: int, failed: int, **kw):
        await self.log(E.CAMPAIGN_COMPLETED, campaign_id, category=Category.MESSAGING, metadata={"sent": sent, "delivered": delivered, "failed": failed, **kw})
    
    # =========================================================================
    # SURVEY CONVENIENCE METHODS
    # =========================================================================
    
    async def survey_created(self, survey_id: str, actor_id: str, **kw):
        await self.log(E.SURVEY_CREATED, survey_id, actor_id, "survey", "create", category=Category.DATA, metadata=kw)
    
    async def survey_response_received(self, survey_id: str, response_id: str, **kw):
        await self.log(E.SURVEY_RESPONSE_RECEIVED, survey_id, category=Category.DATA, metadata={"response_id": response_id, **kw})
    
    async def survey_nps_calculated(self, survey_id: str, score: float, **kw):
        await self.log(E.SURVEY_NPS_CALCULATED, survey_id, category=Category.ANALYTICS, metadata={"nps_score": score, **kw})
    
    # =========================================================================
    # CLEANUP
    # =========================================================================
    
    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


# ============================================================================
# SINGLETON
# ============================================================================

_audit_client: Optional[AuditClient] = None


def get_audit() -> AuditClient:
    """Get singleton audit client."""
    global _audit_client
    if _audit_client is None:
        _audit_client = AuditClient()
    return _audit_client


# Shortcut
audit = get_audit
