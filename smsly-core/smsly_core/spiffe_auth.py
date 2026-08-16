"""
SPIFFE/SPIRE mTLS Authentication Module
========================================
Shared dual-auth (mTLS + HMAC) validation for the HMAC-to-SPIFFE migration.

Phase 2: Services accept BOTH HMAC and mTLS, with mTLS taking priority.
Phase 3: mTLS becomes required (strict mode). HMAC fallback disabled.
Phase 4: HMAC removed entirely. Only mTLS accepted.

Usage:
    from smsly_core.spiffe_auth import (
        DualAuthValidator,
        get_spiffe_feature_flags,
        extract_spiffe_id_from_request,
        is_spiffe_mtls_enabled,
        SPIFFE_TRUST_DOMAIN,
        MigrationPhase,
    )

    # In middleware:
    validator = DualAuthValidator(
        service_name="smsly-rate-limit",
        allowed_callers={"spiffe://smsly.cloud/service/gateway"},
    )
    result = validator.validate(request_headers, method, path)
    if result.authenticated:
        ...
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Set

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SPIFFE_TRUST_DOMAIN = os.getenv("SPIFFE_TRUST_DOMAIN", "smsly.cloud")
SPIFFE_HEADER_ID = "X-SPIFFE-ID"
SPIFFE_AUTHORIZATION_HEADER = "X-SPIFFE-Authorization"

# Allowed SPIFFE ID prefix
SPIFFE_ID_PREFIX = f"spiffe://{SPIFFE_TRUST_DOMAIN}/service/"


# ---------------------------------------------------------------------------
# Migration Phase
# ---------------------------------------------------------------------------

class MigrationPhase(str, Enum):
    """
    Explicit migration phase tracking.
    
    Phase 2: Dual-auth (mTLS priority, HMAC fallback)
    Phase 3: Strict mTLS (HMAC disabled, mTLS required)
    Phase 4: mTLS only (HMAC code removed)
    """
    PHASE_2 = "phase2"
    PHASE_3 = "phase3"
    PHASE_4 = "phase4"


class AuthMethod(str, Enum):
    SPIFFE_MTLS = "spiffe"
    HMAC = "hmac"
    NONE = "none"


# ---------------------------------------------------------------------------
# Feature Flags
# ---------------------------------------------------------------------------

@dataclass
class SPIFFEFeatureFlags:
    """
    Feature flags for the HMAC-to-SPIFFE migration.
    Read from environment variables with safe defaults.
    
    Phase progression is controlled by MIGRATION_PHASE env var:
    - phase2: feature_spiffe_mtls=True, hmac_fallback_enabled=True, spiffe_mtls_strict_mode=False
    - phase3: feature_spiffe_mtls=True, hmac_fallback_enabled=False, spiffe_mtls_strict_mode=True
    - phase4: feature_spiffe_mtls=True, hmac_fallback_enabled=False, spiffe_mtls_strict_mode=True (HMAC code removed)
    """
    feature_spiffe_mtls: bool = True
    spiffe_mtls_strict_mode: bool = False
    hmac_fallback_enabled: bool = True
    auth_metrics_enabled: bool = False
    spiffe_identity_forwarding: bool = False
    caller_svid_validation: bool = False
    migration_phase: MigrationPhase = MigrationPhase.PHASE_2

    @classmethod
    def from_env(cls) -> "SPIFFEFeatureFlags":
        # Determine migration phase from env (default: phase4)
        phase_str = os.getenv("MIGRATION_PHASE", "phase4").lower()
        try:
            phase = MigrationPhase(phase_str)
        except ValueError:
            logger.warning(f"Invalid MIGRATION_PHASE '{phase_str}', defaulting to phase4")
            phase = MigrationPhase.PHASE_4
        
        # Derive flags from phase
        if phase == MigrationPhase.PHASE_2:
            feature_spiffe = True
            strict_mode = False
            hmac_fallback = True
        elif phase == MigrationPhase.PHASE_3:
            feature_spiffe = True
            strict_mode = True
            hmac_fallback = False
        elif phase == MigrationPhase.PHASE_4:
            feature_spiffe = True
            strict_mode = True
            hmac_fallback = False
        else:
            feature_spiffe = True
            strict_mode = False
            hmac_fallback = True
        
        return cls(
            feature_spiffe_mtls=_env_bool("FEATURE_SPIFFE_MTLS", feature_spiffe),
            spiffe_mtls_strict_mode=_env_bool("SPIFFE_MTLS_STRICT_MODE", strict_mode),
            hmac_fallback_enabled=_env_bool("HMAC_FALLBACK_ENABLED", hmac_fallback),
            auth_metrics_enabled=_env_bool("AUTH_METRICS_ENABLED", False),
            spiffe_identity_forwarding=_env_bool("SPIFFE_IDENTITY_FORWARDING", False),
            caller_svid_validation=_env_bool("CALLER_SVID_VALIDATION", False),
            migration_phase=phase,
        )


def _env_bool(key: str, default: bool) -> bool:
    val = os.getenv(key, "").lower()
    if val in ("true", "1", "yes"):
        return True
    if val in ("false", "0", "no"):
        return False
    return default


def get_spiffe_feature_flags() -> SPIFFEFeatureFlags:
    """Get current SPIFFE feature flags from environment."""
    return SPIFFEFeatureFlags.from_env()


def is_spiffe_mtls_enabled() -> bool:
    """Quick check: is SPIFFE mTLS enabled at all?"""
    return _env_bool("FEATURE_SPIFFE_MTLS", True)


# ---------------------------------------------------------------------------
# Auth Result
# ---------------------------------------------------------------------------

@dataclass
class AuthResult:
    """Result of a dual-auth validation attempt."""
    authenticated: bool
    method: AuthMethod = AuthMethod.NONE
    spiffe_id: Optional[str] = None
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# SPIFFE ID Extraction
# ---------------------------------------------------------------------------

def extract_spiffe_id_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """
    Extract SPIFFE ID from request headers.

    The Gateway forwards the caller's SPIFFE ID via X-SPIFFE-ID header
    after mTLS is established. This is the primary source during Phase 3+.

    During Phase 2, we also accept X-SPIFFE-Authorization as an alias.
    """
    # Normalize header keys to lowercase for case-insensitive lookup
    lower_headers = {k.lower(): v for k, v in headers.items()}

    spiffe_id = lower_headers.get(SPIFFE_HEADER_ID.lower())
    if not spiffe_id:
        spiffe_id = lower_headers.get(SPIFFE_AUTHORIZATION_HEADER.lower())

    if spiffe_id and _is_valid_spiffe_id(spiffe_id):
        return spiffe_id
    return None


def _is_valid_spiffe_id(spiffe_id: str) -> bool:
    """Validate SPIFFE ID format and trust domain."""
    if not spiffe_id.startswith("spiffe://"):
        return False
    # Must be under our trust domain
    if not spiffe_id.startswith(f"spiffe://{SPIFFE_TRUST_DOMAIN}/"):
        return False
    # Must be a service identity
    if not spiffe_id.startswith(SPIFFE_ID_PREFIX):
        return False
    # Minimum valid: spiffe://smsly.cloud/service/x
    parts = spiffe_id[len(SPIFFE_ID_PREFIX):]
    if not parts or parts.isspace():
        return False
    return True


# ---------------------------------------------------------------------------
# Dual Auth Validator
# ---------------------------------------------------------------------------

class DualAuthValidator:
    """
    Validates requests using dual-auth strategy (mTLS + HMAC).

    Phase 2: mTLS priority, HMAC fallback.
    Phase 3: mTLS required (strict mode). HMAC disabled.
    Phase 4: mTLS only (HMAC code path removed).

    The validator is stateless — create one per service and reuse.
    """

    def __init__(
        self,
        service_name: str,
        allowed_callers: Optional[Set[str]] = None,
        flags: Optional[SPIFFEFeatureFlags] = None,
    ):
        self.service_name = service_name
        self.allowed_callers = allowed_callers or set()
        self.flags = flags or get_spiffe_feature_flags()
        
        # Log phase on initialization
        logger.info(
            "spiffe_validator_initialized",
            service=service_name,
            phase=self.flags.migration_phase.value,
            spiffe_enabled=self.flags.feature_spiffe_mtls,
            strict_mode=self.flags.spiffe_mtls_strict_mode,
            hmac_fallback=self.flags.hmac_fallback_enabled,
        )

    def validate(
        self,
        headers: Dict[str, str],
        method: str = "",
        path: str = "",
        hmac_validator: Optional[callable] = None,
    ) -> AuthResult:
        """
        Validate a request using the dual-auth strategy.

        Args:
            headers: Request headers dict.
            method: HTTP method (for logging).
            path: Request path (for logging).
            hmac_validator: Callable that returns True if HMAC is valid.
                           Signature: hmac_validator(headers, method, path) -> bool
                           NOTE: In Phase 3+, this parameter is ignored.

        Returns:
            AuthResult indicating whether the request is authenticated.
        """
        flags = self.flags
        phase = flags.migration_phase

        # Phase 4: HMAC is completely removed - reject any HMAC attempt
        if phase == MigrationPhase.PHASE_4:
            if hmac_validator is not None:
                logger.warning(
                    "hmac_attempted_in_phase4",
                    service=self.service_name,
                    path=path,
                    msg="HMAC validation attempted but HMAC is removed in Phase 4",
                )
            # Only accept mTLS
            return self._validate_mtls_only(headers, method, path)

        # Phase 3: Strict mTLS required, HMAC disabled
        if phase == MigrationPhase.PHASE_3:
            return self._validate_phase3(headers, method, path)

        # Phase 2: Dual-auth (mTLS priority, HMAC fallback)
        return self._validate_phase2(headers, method, path, hmac_validator)

    def _validate_mtls_only(self, headers: Dict[str, str], method: str, path: str) -> AuthResult:
        """Phase 4: Only mTLS accepted. HMAC completely removed."""
        if not self.flags.feature_spiffe_mtls:
            logger.error(
                "spiffe_disabled_in_phase4",
                service=self.service_name,
                msg="SPIFFE is disabled but we're in Phase 4 - no auth method available",
            )
            return AuthResult(
                authenticated=False,
                method=AuthMethod.NONE,
                reason="No auth method available (Phase 4 but SPIFFE disabled)",
            )

        spiffe_id = extract_spiffe_id_from_headers(headers)
        if not spiffe_id:
            logger.warning(
                "no_spiffe_id_in_phase4",
                service=self.service_name,
                path=path,
            )
            return AuthResult(
                authenticated=False,
                method=AuthMethod.NONE,
                reason="mTLS required (Phase 4) but no valid SPIFFE identity found",
            )

        # Validate caller if enabled
        if self.flags.caller_svid_validation and self.allowed_callers:
            if spiffe_id not in self.allowed_callers:
                logger.warning(
                    "spiffe_caller_rejected_phase4",
                    service=self.service_name,
                    spiffe_id=spiffe_id,
                    allowed=list(self.allowed_callers),
                )
                return AuthResult(
                    authenticated=False,
                    method=AuthMethod.SPIFFE_MTLS,
                    spiffe_id=spiffe_id,
                    reason=f"SPIFFE ID {spiffe_id} not in allowed callers",
                )

        logger.debug(
            "spiffe_auth_passed_phase4",
            service=self.service_name,
            spiffe_id=spiffe_id,
        )
        if self.flags.auth_metrics_enabled:
            _record_auth_metric("spiffe_phase4", self.service_name)
        return AuthResult(
            authenticated=True,
            method=AuthMethod.SPIFFE_MTLS,
            spiffe_id=spiffe_id,
        )

    def _validate_phase3(self, headers: Dict[str, str], method: str, path: str) -> AuthResult:
        """Phase 3: Strict mTLS required. HMAC disabled but not removed."""
        if not self.flags.feature_spiffe_mtls:
            logger.error(
                "spiffe_disabled_in_phase3",
                service=self.service_name,
                msg="SPIFFE is disabled but we're in Phase 3 - no auth method available",
            )
            return AuthResult(
                authenticated=False,
                method=AuthMethod.NONE,
                reason="No auth method available (Phase 3 but SPIFFE disabled)",
            )

        spiffe_id = extract_spiffe_id_from_headers(headers)
        if not spiffe_id:
            logger.warning(
                "no_spiffe_id_in_phase3",
                service=self.service_name,
                path=path,
            )
            return AuthResult(
                authenticated=False,
                method=AuthMethod.NONE,
                reason="mTLS required (Phase 3) but no valid SPIFFE identity found",
            )

        # Validate caller if enabled
        if self.flags.caller_svid_validation and self.allowed_callers:
            if spiffe_id not in self.allowed_callers:
                logger.warning(
                    "spiffe_caller_rejected_phase3",
                    service=self.service_name,
                    spiffe_id=spiffe_id,
                    allowed=list(self.allowed_callers),
                )
                return AuthResult(
                    authenticated=False,
                    method=AuthMethod.SPIFFE_MTLS,
                    spiffe_id=spiffe_id,
                    reason=f"SPIFFE ID {spiffe_id} not in allowed callers",
                )

        logger.debug(
            "spiffe_auth_passed_phase3",
            service=self.service_name,
            spiffe_id=spiffe_id,
        )
        if self.flags.auth_metrics_enabled:
            _record_auth_metric("spiffe_phase3", self.service_name)
        return AuthResult(
            authenticated=True,
            method=AuthMethod.SPIFFE_MTLS,
            spiffe_id=spiffe_id,
        )

    def _validate_phase2(
        self,
        headers: Dict[str, str],
        method: str,
        path: str,
        hmac_validator: Optional[callable],
    ) -> AuthResult:
        """Phase 2: Dual-auth (mTLS priority, HMAC fallback)."""
        # Try mTLS first if enabled
        if self.flags.feature_spiffe_mtls:
            spiffe_id = extract_spiffe_id_from_headers(headers)
            if spiffe_id:
                # Validate caller identity if caller validation is enabled
                if self.flags.caller_svid_validation and self.allowed_callers:
                    if spiffe_id not in self.allowed_callers:
                        logger.warning(
                            "spiffe_caller_rejected",
                            service=self.service_name,
                            spiffe_id=spiffe_id,
                            allowed=list(self.allowed_callers),
                        )
                        # In Phase 2, fall through to HMAC on caller rejection
                    else:
                        logger.debug(
                            "spiffe_auth_passed",
                            service=self.service_name,
                            spiffe_id=spiffe_id,
                        )
                        if self.flags.auth_metrics_enabled:
                            _record_auth_metric("spiffe", self.service_name)
                        return AuthResult(
                            authenticated=True,
                            method=AuthMethod.SPIFFE_MTLS,
                            spiffe_id=spiffe_id,
                        )
                else:
                    # No caller validation — accept any valid SPIFFE ID under trust domain
                    logger.debug(
                        "spiffe_auth_passed_no_caller_check",
                        service=self.service_name,
                        spiffe_id=spiffe_id,
                    )
                    if self.flags.auth_metrics_enabled:
                        _record_auth_metric("spiffe", self.service_name)
                    return AuthResult(
                        authenticated=True,
                        method=AuthMethod.SPIFFE_MTLS,
                        spiffe_id=spiffe_id,
                    )

        # HMAC fallback (Phase 2 only)
        if hmac_validator and self.flags.hmac_fallback_enabled:
            try:
                if hmac_validator(headers, method, path):
                    logger.debug(
                        "hmac_auth_passed",
                        service=self.service_name,
                        path=path,
                    )
                    if self.flags.auth_metrics_enabled:
                        _record_auth_metric("hmac", self.service_name)
                    return AuthResult(
                        authenticated=True,
                        method=AuthMethod.HMAC,
                    )
            except Exception as e:
                logger.error(
                    "hmac_validation_error",
                    service=self.service_name,
                    error=str(e),
                )

        if self.flags.auth_metrics_enabled:
            _record_auth_metric("rejected", self.service_name)

        return AuthResult(
            authenticated=False,
            method=AuthMethod.NONE,
            reason="Authentication failed",
        )


# ---------------------------------------------------------------------------
# Auth Metrics (Prometheus-compatible)
# ---------------------------------------------------------------------------

_AUTH_METRICS: Dict[str, int] = {}


def _record_auth_metric(method: str, service: str) -> None:
    """Record auth method metric. Replace with Prometheus counter in production."""
    key = f"auth_method_{method}_{service}"
    _AUTH_METRICS[key] = _AUTH_METRICS.get(key, 0) + 1


def get_auth_metrics() -> Dict[str, int]:
    """Get accumulated auth metrics (for debugging / health endpoints)."""
    return dict(_AUTH_METRICS)


# ---------------------------------------------------------------------------
# Allowed Callers Registry
# ---------------------------------------------------------------------------

# Default allowed callers per service — used when CALLER_SVID_VALIDATION=true
DEFAULT_ALLOWED_CALLERS: Dict[str, Set[str]] = {
    "backend": {
        "spiffe://smsly.cloud/service/gateway",
        "spiffe://smsly.cloud/service/platform-api",
    },
    "platform-api": {
        "spiffe://smsly.cloud/service/gateway",
        "spiffe://smsly.cloud/service/backend",
    },
    "identity": {
        "spiffe://smsly.cloud/service/gateway",
        "spiffe://smsly.cloud/service/backend",
        "spiffe://smsly.cloud/service/platform-api",
        "spiffe://smsly.cloud/service/rate-limit",
    },
    "audit": {
        "spiffe://smsly.cloud/service/gateway",
        "spiffe://smsly.cloud/service/platform-api",
        "spiffe://smsly.cloud/service/identity",
        "spiffe://smsly.cloud/service/backend",
        "spiffe://smsly.cloud/service/policy",
        "spiffe://smsly.cloud/service/rate-limit",
    },
    "policy": {
        "spiffe://smsly.cloud/service/gateway",
        "spiffe://smsly.cloud/service/platform-api",
        "spiffe://smsly.cloud/service/rate-limit",
    },
    "rate-limit": {
        "spiffe://smsly.cloud/service/gateway",
        "spiffe://smsly.cloud/service/platform-api",
    },
    "email": {
        "spiffe://smsly.cloud/service/gateway",
        "spiffe://smsly.cloud/service/platform-api",
    },
    "chain": {
        "spiffe://smsly.cloud/service/gateway",
        "spiffe://smsly.cloud/service/platform-api",
        "spiffe://smsly.cloud/service/backend",
        "spiffe://smsly.cloud/service/identity",
    },
}


def get_allowed_callers(service_name: str) -> Set[str]:
    """Get the default allowed callers for a service."""
    return DEFAULT_ALLOWED_CALLERS.get(service_name, set())


# ---------------------------------------------------------------------------
# Gateway Identity Forwarding Helper
# ---------------------------------------------------------------------------

def build_spiffe_forwarding_headers(
    caller_spiffe_id: str,
) -> Dict[str, str]:
    """
    Build headers for the Gateway to forward SPIFFE identity to downstream services.

    The Gateway extracts the caller's SPIFFE ID from the mTLS connection
    and injects it into these headers for downstream services to verify.
    """
    return {
        SPIFFE_HEADER_ID: caller_spiffe_id,
        "X-SPIFFE-Forwarded": "true",
    }
