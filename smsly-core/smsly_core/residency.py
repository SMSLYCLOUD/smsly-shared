"""
Data Residency & Geo-Routing Context (EU GDPR / Multi-Region Data Plane)
========================================================================
Provides canonical data-region normalization, ContextVar request scoping,
zero-PII blind-index hashing for global routing lookups, identifier prefix
detection, fail-closed GDPR enforcement, and pure-ASGI middleware.

Design invariant:
- Live IP GeoIP is ONLY for initial region suggestion at signup/onboarding.
- Once pinned on a tenant (Organization / Account / API Key), EVERY database,
  Redis, S3/object-storage, and audit operation routes strictly by the pinned
  ``data_region`` carried in ``X-Trulay-Data-Region`` / JWT ``dr`` claim.
- When ``EU_RESIDENCY_STRICT=true`` is active, an EU-pinned request NEVER
  falls back to a non-EU datastore; missing EU stores raise DataResidencyError
  and fail closed with HTTP 503.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from contextvars import ContextVar, Token
from typing import Any, Mapping, Optional

REGION_DEFAULT = "default"
REGION_EU = "eu"
REGION_US = "us"

ALLOWED_DATA_REGIONS = frozenset({REGION_DEFAULT, REGION_EU, REGION_US})
_CUSTOM_REGION_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_PREFIXED_ID_RE = re.compile(
    r"^(?:tlk_live|tlk_test|sk_live|sk_test|org|acc|usr|prj|msg|mbx|aud|whk|call)_([a-z][a-z0-9-]{1,15})_"
)

DATA_REGION_HEADER = "X-Trulay-Data-Region"
DATA_REGION_HEADER_LOWER = "x-trulay-data-region"
SMSLY_DATA_REGION_HEADER = "X-Smsly-Data-Region"
SMSLY_DATA_REGION_HEADER_LOWER = "x-smsly-data-region"
LEGACY_DATA_REGION_HEADER_LOWER = "x-data-region"

_RECOGNIZED_ID_REGION_CODES = frozenset({
    "eu", "us", "uk", "gb", "ch", "ca", "au", "nz", "jp", "sg", "in", "br",
    "za", "ng", "ae", "sa", "kr", "de", "fr", "ie", "nl", "se", "es", "it",
    "pl", "no", "is", "li", "mx", "il", "hk", "tw", "id", "my", "th", "vn",
    "ph", "ke", "eg", "ma", "cl", "co", "ar", "eea", "gdpr", "europe",
    "americas", "na", "frankfurt", "dublin",
})
_RECOGNIZED_CLOUD_REGION_RE = re.compile(
    r"^(?:eu|us|ap|me|af|sa|ca|uk|ch)-[a-z0-9-]{2,24}$"
)

# 27 EU Member States (ISO 3166-1 alpha-2)
EU_MEMBER_STATES = frozenset({
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI",
    "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU",
    "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
})

# Additional EEA states subject to GDPR
EEA_EXTRA_COUNTRIES = frozenset({"IS", "LI", "NO"})

# UK GDPR & Swiss FADP (adequacy + commonly grouped with EU data residency)
GDPR_ADEQUATE_EURO_COUNTRIES = frozenset({"GB", "UK", "CH"})

EU_GDPR_COUNTRY_CODES = EU_MEMBER_STATES | EEA_EXTRA_COUNTRIES | GDPR_ADEQUATE_EURO_COUNTRIES

_REGION_ALIASES: dict[str, str] = {
    "": REGION_DEFAULT,
    "default": REGION_DEFAULT,
    "global": REGION_DEFAULT,
    "eu": REGION_EU,
    "eu-central": REGION_EU,
    "eu-central-1": REGION_EU,
    "eu-west": REGION_EU,
    "eu-west-1": REGION_EU,
    "eu-north-1": REGION_EU,
    "eu-south-1": REGION_EU,
    "europe": REGION_EU,
    "eea": REGION_EU,
    "gdpr": REGION_EU,
    "frankfurt": REGION_EU,
    "dublin": REGION_EU,
    "us": REGION_US,
    "us-east": REGION_US,
    "us-east-1": REGION_US,
    "us-west": REGION_US,
    "us-west-2": REGION_US,
    "americas": REGION_US,
    "na": REGION_US,
}

# Region-encoded resource and credential prefixes for O(1) webhook/API routing
_EU_ID_PREFIXES = (
    "tlk_live_eu_",
    "tlk_test_eu_",
    "sk_live_eu_",
    "sk_test_eu_",
    "org_eu_",
    "acc_eu_",
    "usr_eu_",
    "prj_eu_",
    "msg_eu_",
    "mbx_eu_",
    "aud_eu_",
    "whk_eu_",
    "call_eu_",
)

_US_ID_PREFIXES = (
    "tlk_live_us_",
    "tlk_test_us_",
    "sk_live_us_",
    "sk_test_us_",
    "org_us_",
    "acc_us_",
    "usr_us_",
    "prj_us_",
    "msg_us_",
    "mbx_us_",
    "aud_us_",
    "whk_us_",
    "call_us_",
)


class DataResidencyError(RuntimeError):
    """Raised when a regional datastore required for GDPR compliance is unavailable."""

    def __init__(self, message: str, *, data_region: str = REGION_EU, store_type: str = "database") -> None:
        super().__init__(message)
        self.data_region = data_region
        self.store_type = store_type


_current_data_region: ContextVar[str] = ContextVar("trulay_data_region", default=REGION_DEFAULT)


def normalize_data_region(region: Optional[str], *, default: str = REGION_DEFAULT) -> str:
    """Normalize any region alias (e.g. ``eu-central-1`` -> ``eu``) or custom admin slug (e.g. ``ap-sg``)."""
    if not region:
        return default
    cleaned = str(region).strip().lower().replace("_", "-")
    if cleaned in _REGION_ALIASES:
        return _REGION_ALIASES[cleaned]
    if cleaned.startswith("eu-"):
        return REGION_EU
    if cleaned.startswith("us-"):
        return REGION_US
    if _CUSTOM_REGION_RE.match(cleaned):
        return cleaned
    return default


def region_env_suffix(region: Optional[str]) -> str:
    """Convert canonical region slug (e.g. ``eu``, ``ap-sg``) to env-var suffix (``EU``, ``AP_SG``)."""
    norm = normalize_data_region(region)
    if norm == REGION_DEFAULT:
        return ""
    return norm.upper().replace("-", "_")


def is_eu_country(country_code: Optional[str], *, include_uk_ch: Optional[bool] = None) -> bool:
    """Return True if ISO-2 country code falls under EU/EEA GDPR (plus UK/CH when enabled)."""
    if not country_code:
        return False
    code = str(country_code).strip().upper()
    if include_uk_ch is None:
        include_uk_ch = os.getenv("EU_INCLUDE_UK_CH", "true").strip().lower() in ("1", "true", "yes", "on")
    if include_uk_ch:
        return code in EU_GDPR_COUNTRY_CODES
    return code in (EU_MEMBER_STATES | EEA_EXTRA_COUNTRIES)


def resolve_region_for_country(country_code: Optional[str]) -> str:
    """Map an onboarding/legal country code to canonical data residency region."""
    if is_eu_country(country_code):
        return REGION_EU
    return REGION_DEFAULT


def is_eu_residency_strict() -> bool:
    """Return True when missing EU datastores MUST fail closed instead of falling back."""
    raw = os.getenv("EU_RESIDENCY_STRICT", "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return False


def is_region_strict(region: Optional[str]) -> bool:
    """Return True if ``region`` must fail closed (HTTP 503) when its regional store is missing."""
    norm = normalize_data_region(region)
    if norm == REGION_DEFAULT:
        return False
    if norm == REGION_EU and is_eu_residency_strict():
        return True
    raw = os.getenv("DATA_RESIDENCY_STRICT_REGIONS", "").strip()
    if raw:
        strict_set = {normalize_data_region(x) for x in raw.split(",") if x.strip()}
        if norm in strict_set:
            return True
    return False


def get_data_region() -> str:
    """Return the active canonical data region for the current async/sync execution context."""
    return _current_data_region.get()


def set_data_region(region: Optional[str]) -> Token[str]:
    """Bind the canonical data region in the current ContextVar and return its reset token."""
    return _current_data_region.set(normalize_data_region(region))


def reset_data_region(token: Token[str]) -> None:
    """Restore the previous data region ContextVar value."""
    _current_data_region.reset(token)


class _DataRegionContext:
    """Dual sync/async context manager for scoped data-region execution."""

    def __init__(self, region: Optional[str]) -> None:
        self._region = normalize_data_region(region)
        self._token: Optional[Token[str]] = None

    def __enter__(self) -> str:
        self._token = _current_data_region.set(self._region)
        return self._region

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._token is not None:
            _current_data_region.reset(self._token)
            self._token = None

    async def __aenter__(self) -> str:
        return self.__enter__()

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.__exit__(exc_type, exc, tb)


def data_region_context(region: Optional[str]) -> _DataRegionContext:
    """Execute a block pinned to a specific data region (supports ``with`` and ``async with``)."""
    return _DataRegionContext(region)


def _configured_custom_regions() -> frozenset[str]:
    regions: set[str] = set()
    for var in ("DATA_RESIDENCY_REGIONS", "DATA_RESIDENCY_STRICT_REGIONS"):
        raw = os.getenv(var, "").strip()
        if not raw:
            continue
        for item in raw.split(","):
            slug = normalize_data_region(item)
            if slug and slug != REGION_DEFAULT:
                regions.add(slug)
    return frozenset(regions)


def extract_region_from_identifier(value: Optional[str]) -> Optional[str]:
    """Extract canonical data region from region-prefixed keys or IDs (e.g. ``tlk_live_eu_...``, ``org_uk_...``).

    Only recognizes known residency/cloud region codes and configured ``DATA_RESIDENCY_REGIONS``,
    avoiding false positives on arbitrary slugs like ``org_acme_123``.
    """
    if not value:
        return None
    s = str(value).strip().lower()
    if s.startswith(_EU_ID_PREFIXES):
        return REGION_EU
    if s.startswith(_US_ID_PREFIXES):
        return REGION_US
    m = _PREFIXED_ID_RE.match(s)
    if m:
        candidate = m.group(1).replace("_", "-")
        if (
            candidate in _RECOGNIZED_ID_REGION_CODES
            or _RECOGNIZED_CLOUD_REGION_RE.match(candidate)
            or candidate in _configured_custom_regions()
        ):
            norm = normalize_data_region(candidate)
            if norm != REGION_DEFAULT:
                return norm
    return None


def _is_production_env() -> bool:
    env = (
        os.getenv("ENVIRONMENT")
        or os.getenv("DJANGO_ENV")
        or os.getenv("APP_ENV")
        or ""
    ).strip().lower()
    return env in ("production", "prod", "staging")


def blind_index_email(email: str, *, pepper: Optional[str] = None) -> str:
    """Compute a deterministic HMAC-SHA256 blind index for zero-PII global region lookup.

    The global routing directory stores ``email_hmac:<hex>`` -> ``data_region`` so
    pre-authentication login/passkey requests can locate an EU tenant without storing
    raw EU email addresses in a non-EU directory.

    Pepper resolution order is unified across Gateway & Backend:
    explicit ``pepper`` -> ``RESIDENCY_DIRECTORY_PEPPER`` -> ``ENCRYPTION_KEY`` -> ``FIELD_ENCRYPTION_KEY``.
    Fails closed in production when no secret is configured.
    """
    normalized = str(email or "").strip().lower()
    if not normalized:
        raise ValueError("email must not be empty")
    secret = (
        (pepper or "").strip()
        or (os.getenv("RESIDENCY_DIRECTORY_PEPPER") or "").strip()
        or (os.getenv("ENCRYPTION_KEY") or "").strip()
        or (os.getenv("FIELD_ENCRYPTION_KEY") or "").strip()
    )
    if not secret:
        if _is_production_env():
            raise RuntimeError(
                "RESIDENCY_DIRECTORY_PEPPER (or ENCRYPTION_KEY / FIELD_ENCRYPTION_KEY) "
                "must be configured in production for blind_index_email()."
            )
        secret = "trulay-dev-residency-pepper"
    digest = hmac.new(
        secret.encode("utf-8"),
        normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"email_hmac:{digest}"


def resolve_region_from_headers(headers: Mapping[str, Any]) -> str:
    """Read gateway-attested data region header with strict precedence:
    ``X-Trulay-Data-Region`` > ``X-Smsly-Data-Region`` > ``X-Data-Region``.
    """
    if not headers:
        return REGION_DEFAULT
    found: dict[str, str] = {}
    for k, v in headers.items():
        if v is None:
            continue
        kl = str(k).lower()
        if kl in (DATA_REGION_HEADER_LOWER, SMSLY_DATA_REGION_HEADER_LOWER, LEGACY_DATA_REGION_HEADER_LOWER):
            val = str(v).strip()
            if val and kl not in found:
                found[kl] = val
    raw = (
        found.get(DATA_REGION_HEADER_LOWER)
        or found.get(SMSLY_DATA_REGION_HEADER_LOWER)
        or found.get(LEGACY_DATA_REGION_HEADER_LOWER)
    )
    return normalize_data_region(raw)


class DataRegionMiddleware:
    """Pure ASGI middleware that binds ``X-Trulay-Data-Region`` into ContextVar.

    - Reads the gateway-attested region header with strict precedence:
      ``X-Trulay-Data-Region`` > ``X-Smsly-Data-Region`` > ``X-Data-Region``.
    - Stores ``region`` in ``scope["state"]["data_region"]`` (accessible as ``request.state.data_region``).
    - Echoes ``X-Trulay-Data-Region`` on HTTP responses for auditability.
    - Catches ``DataResidencyError`` and returns HTTP 503 JSON cleanly (fail-closed GDPR).
    """

    def __init__(self, app: Any, *, default_region: str = REGION_DEFAULT) -> None:
        self.app = app
        self.default_region = normalize_data_region(default_region)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        scope_type = scope.get("type")
        if scope_type not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        found_headers: dict[str, str] = {}
        for raw_key, raw_val in scope.get("headers") or ():
            key = raw_key.decode("latin-1").lower()
            if key in (DATA_REGION_HEADER_LOWER, SMSLY_DATA_REGION_HEADER_LOWER, LEGACY_DATA_REGION_HEADER_LOWER):
                val = raw_val.decode("latin-1").strip()
                if val and key not in found_headers:
                    found_headers[key] = val

        chosen = (
            found_headers.get(DATA_REGION_HEADER_LOWER)
            or found_headers.get(SMSLY_DATA_REGION_HEADER_LOWER)
            or found_headers.get(LEGACY_DATA_REGION_HEADER_LOWER)
        )
        region = normalize_data_region(chosen, default=self.default_region) if chosen else self.default_region

        state = scope.setdefault("state", {})
        if isinstance(state, dict):
            state["data_region"] = region

        token = set_data_region(region)
        response_started = False

        async def _send_with_region_header(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
                headers = list(message.get("headers") or [])
                has_hdr = any(k.lower() == b"x-trulay-data-region" for k, _ in headers)
                if not has_hdr:
                    headers.append((b"x-trulay-data-region", region.encode("latin-1")))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, _send_with_region_header if scope_type == "http" else send)
        except DataResidencyError as exc:
            if scope_type == "http" and not response_started:
                payload = json.dumps({
                    "error": "regional_data_store_unavailable",
                    "detail": str(exc),
                    "data_region": exc.data_region,
                    "store_type": exc.store_type,
                }).encode("utf-8")
                await send({
                    "type": "http.response.start",
                    "status": 503,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"x-trulay-data-region", region.encode("latin-1")),
                    ],
                })
                await send({
                    "type": "http.response.body",
                    "body": payload,
                    "more_body": False,
                })
                return
            raise
        finally:
            reset_data_region(token)


__all__ = [
    "REGION_DEFAULT",
    "REGION_EU",
    "REGION_US",
    "ALLOWED_DATA_REGIONS",
    "DATA_REGION_HEADER",
    "DATA_REGION_HEADER_LOWER",
    "SMSLY_DATA_REGION_HEADER",
    "SMSLY_DATA_REGION_HEADER_LOWER",
    "LEGACY_DATA_REGION_HEADER_LOWER",
    "EU_MEMBER_STATES",
    "EEA_EXTRA_COUNTRIES",
    "GDPR_ADEQUATE_EURO_COUNTRIES",
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
]
