"""
SMSLY Core Library
==================
Shared utilities for SMSLYCLOUD microservices.
"""

__version__ = "0.5.0"

# ---------------------------------------------------------------------------
# Structured logging compatibility (stdlib loggers that receive structlog-style
# keyword arguments). Installed first so any module-level `logging.getLogger`
# created afterwards accepts them instead of raising TypeError.
# ---------------------------------------------------------------------------
from smsly_core.structured_logging import (  # noqa: E402
    KwArgLogger,
    install_structured_logger,
)

install_structured_logger()

# Data Residency & Geo-Routing (EU GDPR)
from smsly_core.residency import (
    REGION_DEFAULT,
    REGION_EU,
    REGION_US,
    ALLOWED_DATA_REGIONS,
    DATA_REGION_HEADER,
    EU_MEMBER_STATES,
    EU_GDPR_COUNTRY_CODES,
    DataResidencyError,
    DataRegionMiddleware,
    normalize_data_region,
    region_env_suffix,
    is_eu_country,
    resolve_region_for_country,
    is_eu_residency_strict,
    is_region_strict,
    get_data_region,
    set_data_region,
    reset_data_region,
    data_region_context,
    extract_region_from_identifier,
    blind_index_email,
    resolve_region_from_headers,
)

# Database (multi-region aware)
from smsly_core.database import (
    create_async_engine,
    get_db,
    get_engine,
    get_all_engines,
    get_session,
    AsyncSessionLocal,
    register_regional_engine,
    init_regional_engines,
    create_tables_all_regions,
    check_all_databases_health,
    close_engine,
    close_db,
    close_all_engines,
    prepare_asyncpg_url_and_ssl,
)

# Multi-region Redis Router
from smsly_core.redis_router import (
    RegionalRedisRouter,
    init_regional_redis,
    get_regional_redis_router,
    get_regional_redis,
    close_regional_redis,
    reset_regional_redis_router,
)

# Multi-region S3 / Object Storage
from smsly_core.s3_storage import (
    S3Config,
    S3StorageAdapter,
    RegionalS3Router,
)

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

# Internal Auth (Phase 4: HMAC removed, only SPIFFE mTLS accepted)
# Legacy HMAC functions deprecated - use DualAuthValidator from spiffe_auth
from smsly_core.internal_auth import (
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

# Webhook Validators (NEW)
from smsly_core.webhook_validators import (
    validate_twilio_signature,
    validate_whatsapp_signature,
    validate_stripe_signature,
    validate_coinbase_signature,
)

# Ledger (NEW)
from smsly_core.ledger import (
    RequestLedger,
    RequestLedgerSync,
    TraceStage,
)

# Transaction Chain client (NEW — backend payments + email lifecycle)
from smsly_core.transaction_chain import (
    queue_transaction_sync,
    queue_transactions_bulk_sync,
    queue_transaction_async,
    queue_transaction,
)

# SPIFFE mTLS helpers (dual-port: :8080 Traefik HTTP, :8443 direct mTLS)
from smsly_core.mtls import (
    MESH_HTTP_PORT,
    MESH_MTLS_PORT,
    REFRESH_THRESHOLD_SECONDS,
    is_spire_available,
    create_client_ssl_context,
    create_server_ssl_context,
    create_mesh_client_context,
    create_mtls_httpx_client,
    verify_for_url,
    direct_mtls_url,
    build_tag,
    is_stale,
    get_svid_not_after,
    svid_expiring_soon,
    is_cert_expired_error,
    start_svid_watcher,
)

# Mesh URL helpers (placeholder detection)
from smsly_core.mesh import (
    PLACEHOLDER_HOST_SUFFIXES,
    is_placeholder_mesh_url,
    is_internal_mesh_url,
)

__all__ = [
    # Data Residency & Geo-Routing
    "REGION_DEFAULT",
    "REGION_EU",
    "REGION_US",
    "ALLOWED_DATA_REGIONS",
    "DATA_REGION_HEADER",
    "EU_MEMBER_STATES",
    "EU_GDPR_COUNTRY_CODES",
    "DataResidencyError",
    "DataRegionMiddleware",
    "normalize_data_region",
    "region_env_suffix",
    "is_eu_country",
    "resolve_region_for_country",
    "is_eu_residency_strict",
    "is_region_strict",
    "get_data_region",
    "set_data_region",
    "reset_data_region",
    "data_region_context",
    "extract_region_from_identifier",
    "blind_index_email",
    "resolve_region_from_headers",
    # Database
    "create_async_engine",
    "get_db",
    "get_engine",
    "get_all_engines",
    "get_session",
    "AsyncSessionLocal",
    "register_regional_engine",
    "init_regional_engines",
    "create_tables_all_regions",
    "check_all_databases_health",
    "close_engine",
    "close_db",
    "close_all_engines",
    "prepare_asyncpg_url_and_ssl",
    # Multi-region Redis Router
    "RegionalRedisRouter",
    "init_regional_redis",
    "get_regional_redis_router",
    "get_regional_redis",
    "close_regional_redis",
    "reset_regional_redis_router",
    # Multi-region S3 / Object Storage
    "S3Config",
    "S3StorageAdapter",
    "RegionalS3Router",
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
    # Internal Auth (Phase 4: HMAC removed)
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
    # Transaction Chain client
    "queue_transaction_sync",
    "queue_transactions_bulk_sync",
    "queue_transaction_async",
    "queue_transaction",
    # SPIFFE mTLS helpers
    "MESH_HTTP_PORT",
    "MESH_MTLS_PORT",
    "REFRESH_THRESHOLD_SECONDS",
    "is_spire_available",
    "create_client_ssl_context",
    "create_server_ssl_context",
    "create_mesh_client_context",
    "create_mtls_httpx_client",
    "verify_for_url",
    "direct_mtls_url",
    "build_tag",
    "is_stale",
    "get_svid_not_after",
    "svid_expiring_soon",
    "is_cert_expired_error",
    "start_svid_watcher",
    # Mesh URL helpers
    "PLACEHOLDER_HOST_SUFFIXES",
    "is_placeholder_mesh_url",
    "is_internal_mesh_url",
    # Structured logging compatibility
    "KwArgLogger",
    "install_structured_logger",
]

