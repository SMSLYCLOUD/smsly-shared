"""
SMSLY Core Library
==================
Shared utilities for SMSLYCLOUD microservices.
"""

__version__ = "0.5.0"

# Database
from smsly_core.database import create_async_engine, get_db, AsyncSessionLocal

# Health
from smsly_core.health import create_health_router

# API Keys
from smsly_core.api_keys import (
    generate_api_key,
    generate_test_key,
    hash_api_key,
    validate_api_key,
    mask_api_key,
    APIKeyScope,
    APIKeyInfo,
)

# Audit
from smsly_core.audit import (
    AuditEventType,
    AuditEvent,
    AuditLogger,
    compute_event_hash,
    verify_chain_integrity,
)

# Internal Auth
from smsly_core.internal_auth import (
    compute_signature,
    verify_signature,
    create_signed_headers,
    AuthDecision,
    AuthResult,
    NonceCache,
)

# Rate Limiting
from smsly_core.rate_limit import (
    InMemoryRateLimiter,
    RedisRateLimiter,
    SlidingWindowLimiter,
    RateLimitInfo,
    RateLimitResult,
)

# Messaging
from smsly_core.messaging import (
    detect_encoding,
    calculate_segments,
    split_message,
    validate_e164,
    normalize_phone,
    sanitize_sender_id,
    EncodingType,
)

# OTP
from smsly_core.otp import (
    generate_otp,
    hash_otp,
    verify_otp_hash,
    OTPGenerator,
    OTPSession,
    OTPConfig,
    OTPMethod,
    ProofToken,
)

# Retry
from smsly_core.retry import (
    retry_with_backoff,
    with_retry,
    CircuitBreaker,
    CircuitBreakerOpen,
    RetryExhausted,
)

# WhatsApp
from smsly_core.whatsapp import (
    WhatsAppTemplate,
    TemplateManager,
    SessionManager,
    TemplateCategory,
    TemplateStatus,
)

# Metrics
from smsly_core.metrics import (
    SimpleMetrics,
    MetricLabels,
    Timer,
    MetricNames,
)

# Admin Client
from smsly_core.admin_client import (
    AdminClient,
    AdminConfig,
    get_admin_client,
)

# Password Hashing (NEW)
from smsly_core.password import (
    hash_password,
    verify_password,
    verify_and_upgrade,
    needs_rehash,
    hash_password_sync,
    verify_password_sync,
)

# Circuit Breaker (NEW)
from smsly_core.circuit_breaker import (
    CircuitBreaker as AsyncCircuitBreaker,
    CircuitBreakerError,
    CircuitBreakerConfig,
    CircuitState,
    circuit_breaker,
    get_breaker,
    get_breaker_sync,
    get_all_breaker_metrics,
    reset_breaker,
    reset_all_breakers,
)

# Inter-Service Metrics (NEW)
from smsly_core.inter_service_metrics import (
    InstrumentedClient,
    record_service_call,
    record_circuit_state,
    record_error,
    track_service_call,
    get_metrics_app,
    get_metrics_text,
)

# Direct Access Protection (NEW)
from smsly_core.direct_access import (
    DirectAccessProtectionMiddleware,
    is_gateway_ip,
    is_internal_ip,
    get_direct_access_stats,
)

# Ledger (NEW)
from smsly_core.ledger import (
    RequestLedger,
    RequestLedgerSync,
    TraceStage,
)

__all__ = [
    # Database
    "create_async_engine",
    "get_db",
    "AsyncSessionLocal",
    # Health
    "create_health_router",
    # API Keys
    "generate_api_key",
    "generate_test_key",
    "hash_api_key",
    "validate_api_key",
    "mask_api_key",
    "APIKeyScope",
    "APIKeyInfo",
    # Audit
    "AuditEventType",
    "AuditEvent",
    "AuditLogger",
    "compute_event_hash",
    "verify_chain_integrity",
    # Internal Auth
    "compute_signature",
    "verify_signature",
    "create_signed_headers",
    "AuthDecision",
    "AuthResult",
    "NonceCache",
    # Rate Limiting
    "InMemoryRateLimiter",
    "RedisRateLimiter",
    "SlidingWindowLimiter",
    "RateLimitInfo",
    "RateLimitResult",
    # Messaging
    "detect_encoding",
    "calculate_segments",
    "split_message",
    "validate_e164",
    "normalize_phone",
    "sanitize_sender_id",
    "EncodingType",
    # OTP
    "generate_otp",
    "hash_otp",
    "verify_otp_hash",
    "OTPGenerator",
    "OTPSession",
    "OTPConfig",
    "OTPMethod",
    "ProofToken",
    # Retry
    "retry_with_backoff",
    "with_retry",
    "CircuitBreaker",
    "CircuitBreakerOpen",
    "RetryExhausted",
    # WhatsApp
    "WhatsAppTemplate",
    "TemplateManager",
    "SessionManager",
    "TemplateCategory",
    "TemplateStatus",
    # Metrics
    "SimpleMetrics",
    "MetricLabels",
    "Timer",
    "MetricNames",
    # Admin Client
    "AdminClient",
    "AdminConfig",
    "get_admin_client",
    # Password Hashing (NEW)
    "hash_password",
    "verify_password",
    "verify_and_upgrade",
    "needs_rehash",
    "hash_password_sync",
    "verify_password_sync",
    # Circuit Breaker (NEW)
    "AsyncCircuitBreaker",
    "CircuitBreakerError",
    "CircuitBreakerConfig",
    "CircuitState",
    "circuit_breaker",
    "get_breaker",
    "get_breaker_sync",
    "get_all_breaker_metrics",
    "reset_breaker",
    "reset_all_breakers",
    # Inter-Service Metrics (NEW)
    "InstrumentedClient",
    "record_service_call",
    "record_circuit_state",
    "record_error",
    "track_service_call",
    "get_metrics_app",
    "get_metrics_text",
    # Direct Access Protection (NEW)
    "DirectAccessProtectionMiddleware",
    "is_gateway_ip",
    "is_internal_ip",
    "get_direct_access_stats",
    # Ledger
    "RequestLedger",
    "RequestLedgerSync",
    "TraceStage",
]

