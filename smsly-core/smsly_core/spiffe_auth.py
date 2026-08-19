"""
SPIFFE/SPIRE mTLS Authentication Module
========================================
Phase 4: HMAC removed. Only mTLS accepted.

Validates incoming requests by verifying the peer's X.509 SVID
certificate from the TLS handshake. The SPIFFE ID is extracted
from the certificate, not from headers.

Usage:
    from smsly_core.spiffe_auth import (
        DualAuthValidator,
        get_spiffe_feature_flags,
        extract_spiffe_id_from_cert,
        is_spiffe_mtls_enabled,
        SPIFFE_TRUST_DOMAIN,
    )

    # In middleware:
    validator = DualAuthValidator(
        service_name="smsly-rate-limit",
        allowed_callers={"spiffe://trulay.co/service/gateway"},
    )
    result = validator.validate(
        peer_cert_der=peer_certificate_bytes,
        method=request.method,
        path=request.url.path,
    )
    if result.authenticated:
        ...
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, Optional, Set

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SPIFFE_TRUST_DOMAIN = os.getenv("SPIFFE_TRUST_DOMAIN", "trulay.co")
SPIFFE_ID_PREFIX = f"spiffe://{SPIFFE_TRUST_DOMAIN}/service/"

# SPIFFE OID: 1.3.6.1.4.1.57264.1.1
SPIFFE_OID_DOTTED = "1.3.6.1.4.1.57264.1.1"


# ---------------------------------------------------------------------------
# Feature Flags (Phase 4 only)
# ---------------------------------------------------------------------------

@dataclass
class SPIFFEFeatureFlags:
    """
    Feature flags for mTLS authentication.
    Phase 4: HMAC removed, mTLS required.
    """
    feature_spiffe_mtls: bool = True
    spiffe_mtls_strict_mode: bool = True
    hmac_fallback_enabled: bool = False
    auth_metrics_enabled: bool = False
    spiffe_identity_forwarding: bool = True
    caller_svid_validation: bool = True
    migration_phase: str = "phase4"

    @classmethod
    def from_env(cls) -> "SPIFFEFeatureFlags":
        return cls(
            feature_spiffe_mtls=_env_bool("FEATURE_SPIFFE_MTLS", True),
            spiffe_mtls_strict_mode=_env_bool("SPIFFE_MTLS_STRICT_MODE", True),
            hmac_fallback_enabled=_env_bool("HMAC_FALLBACK_ENABLED", False),
            auth_metrics_enabled=_env_bool("AUTH_METRICS_ENABLED", False),
            spiffe_identity_forwarding=_env_bool("SPIFFE_IDENTITY_FORWARDING", True),
            caller_svid_validation=_env_bool("CALLER_SVID_VALIDATION", True),
            migration_phase=os.getenv("MIGRATION_PHASE", "phase4"),
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
    """Quick check: is SPIFFE mTLS enabled?"""
    return _env_bool("FEATURE_SPIFFE_MTLS", True)


# ---------------------------------------------------------------------------
# Auth Result
# ---------------------------------------------------------------------------

@dataclass
class AuthResult:
    """Result of mTLS validation attempt."""
    authenticated: bool
    method: str = "spiffe"
    spiffe_id: Optional[str] = None
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# SPIFFE ID Extraction from Certificate
# ---------------------------------------------------------------------------

def extract_spiffe_id_from_cert(peer_cert_der: bytes) -> Optional[str]:
    """
    Extract SPIFFE ID from a peer's X.509 certificate (DER-encoded).

    Looks for the SPIFFE OID (1.3.6.1.4.1.57264.1.1) in the certificate
    extensions, or URI SANs starting with "spiffe://".

    Args:
        peer_cert_der: DER-encoded X.509 certificate from TLS handshake.

    Returns:
        SPIFFE ID string or None.
    """
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(peer_cert_der)
        return _extract_spiffe_from_cert_obj(cert)
    except ImportError:
        logger.error("cryptography library required for SPIFFE ID extraction")
        return None
    except Exception as e:
        logger.warning("Failed to extract SPIFFE ID from cert: %s", e)
        return None


def extract_spiffe_id_from_pem(cert_pem: bytes) -> Optional[str]:
    """Extract SPIFFE ID from a PEM-encoded certificate."""
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_pem)
        return _extract_spiffe_from_cert_obj(cert)
    except Exception as e:
        logger.warning("Failed to extract SPIFFE ID from PEM cert: %s", e)
        return None


def _extract_spiffe_from_cert_obj(cert) -> Optional[str]:
    """Extract SPIFFE ID from a cryptography.x509.Certificate object."""
    try:
        from cryptography import x509

        # Method 1: SPIFFE OID extension
        SPIFFE_OID = x509.ObjectIdentifier(SPIFFE_OID_DOTTED)
        try:
            san_ext = cert.extensions.get_extension_for_oid(SPIFFE_OID)
            spiffe_id = str(san_ext.value.value)
            if _is_valid_spiffe_id(spiffe_id):
                return spiffe_id
        except x509.ExtensionNotFound:
            pass

        # Method 2: URI SAN entries
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            for uri in san_ext.value.get_values_for_type(
                x509.UniformResourceIdentifier
            ):
                if uri.startswith("spiffe://") and _is_valid_spiffe_id(uri):
                    return uri
        except x509.ExtensionNotFound:
            pass

    except ImportError:
        pass

    return None


def _is_valid_spiffe_id(spiffe_id: str) -> bool:
    """Validate SPIFFE ID format and trust domain."""
    if not spiffe_id.startswith("spiffe://"):
        return False
    if not spiffe_id.startswith(f"spiffe://{SPIFFE_TRUST_DOMAIN}/"):
        return False
    if not spiffe_id.startswith(SPIFFE_ID_PREFIX):
        return False
    parts = spiffe_id[len(SPIFFE_ID_PREFIX):]
    if not parts or parts.isspace():
        return False
    return True


# ---------------------------------------------------------------------------
# mTLS Validator
# ---------------------------------------------------------------------------

class DualAuthValidator:
    """
    Validates requests using mTLS (Phase 4).

    Extracts SPIFFE ID from the peer's X.509 SVID certificate.
    HMAC is completely removed — only mTLS is accepted.

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

        logger.info(
            "spiffe_validator_initialized",
            service=service_name,
            phase=self.flags.migration_phase,
            spiffe_enabled=self.flags.feature_spiffe_mtls,
            strict_mode=self.flags.spiffe_mtls_strict_mode,
        )

    def validate(
        self,
        peer_cert_der: Optional[bytes] = None,
        spiffe_id: Optional[str] = None,
        method: str = "",
        path: str = "",
    ) -> AuthResult:
        """
        Validate a request using mTLS.

        Args:
            peer_cert_der: DER-encoded peer certificate from TLS handshake.
                          If provided, SPIFFE ID is extracted from the cert.
            spiffe_id: Pre-extracted SPIFFE ID (e.g., from Gateway forwarding).
                      Only used if peer_cert_der is not provided.
            method: HTTP method (for logging).
            path: Request path (for logging).

        Returns:
            AuthResult indicating whether the request is authenticated.
        """
        if not self.flags.feature_spiffe_mtls:
            logger.error(
                "spiffe_disabled_in_phase4",
                service=self.service_name,
                msg="SPIFFE is disabled but we're in Phase 4",
            )
            return AuthResult(
                authenticated=False,
                method="none",
                reason="No auth method available (Phase 4 but SPIFFE disabled)",
            )

        # Extract SPIFFE ID from certificate if provided
        extracted_spiffe_id = None
        if peer_cert_der:
            extracted_spiffe_id = extract_spiffe_id_from_cert(peer_cert_der)
        elif spiffe_id and _is_valid_spiffe_id(spiffe_id):
            extracted_spiffe_id = spiffe_id

        if not extracted_spiffe_id:
            logger.warning(
                "no_spiffe_id",
                service=self.service_name,
                path=path,
                has_cert=peer_cert_der is not None,
            )
            return AuthResult(
                authenticated=False,
                method="none",
                reason="mTLS required but no valid SPIFFE identity found",
            )

        # Validate caller if enabled
        if self.flags.caller_svid_validation and self.allowed_callers:
            if extracted_spiffe_id not in self.allowed_callers:
                logger.warning(
                    "spiffe_caller_rejected",
                    service=self.service_name,
                    spiffe_id=extracted_spiffe_id,
                    allowed=list(self.allowed_callers),
                )
                return AuthResult(
                    authenticated=False,
                    method="spiffe",
                    spiffe_id=extracted_spiffe_id,
                    reason=f"SPIFFE ID {extracted_spiffe_id} not in allowed callers",
                )

        logger.debug(
            "spiffe_auth_passed",
            service=self.service_name,
            spiffe_id=extracted_spiffe_id,
        )
        if self.flags.auth_metrics_enabled:
            _record_auth_metric("spiffe", self.service_name)

        return AuthResult(
            authenticated=True,
            method="spiffe",
            spiffe_id=extracted_spiffe_id,
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
# Loaded from INFRA/spire/communication_rules.json at startup.
# Falls back to hardcoded defaults if the file is not found.

import json as _json
import os as _os
from pathlib import Path as _Path

def _load_communication_rules() -> Dict[str, Set[str]]:
    """Load service communication rules from communication_rules.json."""
    # Try multiple locations
    candidates = [
        _os.environ.get("COMMUNICATION_RULES_PATH", ""),
        str(_Path(__file__).parent.parent.parent.parent.parent / "INFRA" / "spire" / "communication_rules.json"),
        "/opt/spire/communication_rules.json",
    ]
    
    rules_file = None
    for candidate in candidates:
        if candidate and _Path(candidate).is_file():
            rules_file = candidate
            break
    
    if not rules_file:
        return _FALLBACK_ALLOWED_CALLERS
    
    try:
        with open(rules_file) as f:
            data = _json.load(f)
        
        # Resolve {trust_domain} placeholder
        trust_domain = _os.environ.get("SPIFFE_TRUST_DOMAIN", "trulay.co")
        
        rules = data.get("rules", {})
        result: Dict[str, Set[str]] = {}
        
        for svc_name, svc_rules in rules.items():
            callers = svc_rules.get("allowed_callers", [])
            # Resolve placeholders and filter wildcards
            resolved = set()
            for caller in callers:
                if caller == "*":
                    resolved.add("*")
                else:
                    resolved.add(caller.replace("{trust_domain}", trust_domain))
            result[svc_name] = resolved
        
        return result
    except Exception:
        return _FALLBACK_ALLOWED_CALLERS


# Hardcoded fallback (used when communication_rules.json is not available)
# This is intentionally empty — rules should be configured per-deployment
_FALLBACK_ALLOWED_CALLERS: Dict[str, Set[str]] = {}

# Load rules at module import time
DEFAULT_ALLOWED_CALLERS = _load_communication_rules()


def get_allowed_callers(service_name: str) -> Set[str]:
    """Get the default allowed callers for a service."""
    return DEFAULT_ALLOWED_CALLERS.get(service_name, set())


# ---------------------------------------------------------------------------
# Gateway Identity Forwarding Helper
# ---------------------------------------------------------------------------

def build_spiffe_forwarding_headers(caller_spiffe_id: str) -> Dict[str, str]:
    """
    Build headers for the Gateway to forward SPIFFE identity.

    The Gateway extracts the caller's SPIFFE ID from the mTLS connection
    and injects it into these headers for downstream services to verify.
    """
    return {
        "X-SPIFFE-ID": caller_spiffe_id,
        "X-SPIFFE-Forwarded": "true",
    }
