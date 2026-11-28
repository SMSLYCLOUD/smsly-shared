"""
Multi-Region Redis Router (EU GDPR / Geo-Residency)
===================================================
Provides region-routed async and sync Redis pools keyed by ``data_region``
(``default``, ``eu``, ``us``) from a single microservice deployment.

Environment variables (with optional ``SERVICE_PREFIX``):
- ``REDIS_URL`` (default/global)
- ``REDIS_URL_EU`` / ``EU_REDIS_URL`` (EU GDPR residency Redis)
- ``REDIS_URL_US`` / ``US_REDIS_URL`` (optional explicit US Redis)
- ``EU_RESIDENCY_STRICT=true`` -> fails closed with ``DataResidencyError`` if
  an EU request has no EU Redis configured.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, Optional

import structlog

from smsly_core.residency import (
    DataResidencyError,
    REGION_DEFAULT,
    REGION_EU,
    REGION_US,
    get_data_region,
    is_eu_residency_strict,
    is_region_strict,
    normalize_data_region,
    region_env_suffix,
)

logger = structlog.get_logger(__name__)


def _discover_redis_url(region: str, env_prefix: str = "") -> Optional[str]:
    pfx = f"{env_prefix.strip('_').upper()}_" if env_prefix else ""
    norm = normalize_data_region(region)
    if norm == REGION_DEFAULT:
        candidates = (
            f"{pfx}REDIS_URL" if pfx else "",
            "REDIS_URL",
        )
    else:
        tag = region_env_suffix(norm)
        candidates = (
            f"{pfx}REDIS_URL_{tag}" if pfx else "",
            f"{pfx}{tag}_REDIS_URL" if pfx else "",
            f"REDIS_URL_{tag}",
            f"{tag}_REDIS_URL",
        )
    for var in candidates:
        if not var:
            continue
        val = os.getenv(var, "").strip()
        if val:
            return val
    return None


class RegionalRedisRouter:
    """Async Redis client router supporting multiple regional Redis instances."""

    def __init__(
        self,
        *,
        default_url: Optional[str] = None,
        eu_url: Optional[str] = None,
        us_url: Optional[str] = None,
        env_prefix: str = "",
        decode_responses: bool = True,
        socket_connect_timeout: float = 2.0,
        socket_timeout: float = 2.0,
        max_connections: int = 50,
        strict_eu: Optional[bool] = None,
    ) -> None:
        self._env_prefix = env_prefix
        self._decode_responses = decode_responses
        self._socket_connect_timeout = socket_connect_timeout
        self._socket_timeout = socket_timeout
        self._max_connections = max_connections
        self._strict_eu_override = strict_eu

        self._urls: Dict[str, str] = {}
        self._clients: Dict[str, Any] = {}
        self._lock = asyncio.Lock()

        d_url = default_url or _discover_redis_url(REGION_DEFAULT, env_prefix=env_prefix)
        if d_url:
            self._urls[REGION_DEFAULT] = d_url
        e_url = eu_url or _discover_redis_url(REGION_EU, env_prefix=env_prefix)
        if e_url:
            self._urls[REGION_EU] = e_url
        u_url = us_url or _discover_redis_url(REGION_US, env_prefix=env_prefix)
        if u_url:
            self._urls[REGION_US] = u_url

        # Auto-discover any admin-configured custom regional Redis URLs
        self._discover_custom_regions()

    def _discover_custom_regions(self) -> None:
        extra: list[str] = []
        for raw in os.getenv("DATA_RESIDENCY_REGIONS", "").split(","):
            slug = normalize_data_region(raw)
            if slug not in (REGION_DEFAULT, REGION_EU, REGION_US) and slug not in extra:
                extra.append(slug)
        pfx = f"{self._env_prefix.strip('_').upper()}_" if self._env_prefix else ""
        redis_pfx = f"{pfx}REDIS_URL_"
        for env_k in os.environ.keys():
            if env_k.startswith(redis_pfx):
                tag = env_k[len(redis_pfx):].strip().lower().replace("_", "-")
                if tag and tag not in ("default", "primary", "replica", REGION_EU, REGION_US):
                    norm = normalize_data_region(tag)
                    if norm != REGION_DEFAULT and norm not in extra:
                        extra.append(norm)
        for region in extra:
            if region not in self._urls:
                url = _discover_redis_url(region, env_prefix=self._env_prefix)
                if url:
                    self._urls[region] = url

    def configure_region(self, region: str, url: str) -> None:
        """Register or update the Redis URL for a region."""
        norm = normalize_data_region(region)
        self._urls[norm] = url.strip()

    def bind_client(self, region: str, client: Any) -> None:
        """Bind an already-created Redis client (e.g. from lifespan or tests) to a region."""
        norm = normalize_data_region(region)
        self._clients[norm] = client

    def configured_regions(self) -> tuple[str, ...]:
        self._discover_custom_regions()
        return tuple(sorted(set(self._urls.keys()) | set(self._clients.keys())))

    def _resolve_region(self, region: Optional[str] = None) -> str:
        target = normalize_data_region(region if region is not None else get_data_region())
        if target in self._clients or target in self._urls:
            return target

        if target != REGION_DEFAULT:
            discovered = _discover_redis_url(target, env_prefix=self._env_prefix)
            if discovered:
                self._urls[target] = discovered
                return target

        strict_eu = self._strict_eu_override if self._strict_eu_override is not None else is_eu_residency_strict()
        is_strict = (target == REGION_EU and strict_eu) or (target != REGION_EU and is_region_strict(target))
        if is_strict:
            suffix = region_env_suffix(target)
            raise DataResidencyError(
                f"Regional Redis store (REDIS_URL_{suffix}) is required under strict residency enforcement.",
                data_region=target,
                store_type="redis",
            )

        if REGION_DEFAULT in self._clients or REGION_DEFAULT in self._urls:
            if target == REGION_EU:
                logger.warning("eu_redis_unconfigured_falling_back_to_default", data_region=target)
            return REGION_DEFAULT

        raise RuntimeError(f"No Redis configured for region '{target}' or 'default'.")

    async def get_client(self, region: Optional[str] = None, *, verify_ping: bool = False) -> Any:
        """Return an async Redis client routed to ``region`` or the active ContextVar region."""
        resolved = self._resolve_region(region)
        existing = self._clients.get(resolved)
        if existing is not None:
            return existing

        async with self._lock:
            existing = self._clients.get(resolved)
            if existing is not None:
                return existing

            url = self._urls.get(resolved)
            if not url:
                raise RuntimeError(f"No Redis URL configured for region '{resolved}'.")

            import redis.asyncio as aioredis

            client = aioredis.from_url(
                url,
                decode_responses=self._decode_responses,
                socket_connect_timeout=self._socket_connect_timeout,
                socket_timeout=self._socket_timeout,
                max_connections=self._max_connections,
            )
            if verify_ping:
                await client.ping()
            self._clients[resolved] = client
            return client

    async def ping_all(self) -> Dict[str, bool]:
        """Ping all configured regional Redis instances."""
        status: Dict[str, bool] = {}
        for region in self.configured_regions():
            try:
                client = await self.get_client(region=region)
                await client.ping()
                status[region] = True
            except Exception as exc:
                logger.warning("regional_redis_ping_failed", data_region=region, error=str(exc))
                status[region] = False
        return status

    async def close_all(self) -> None:
        """Close all initialized Redis clients across regions."""
        for region, client in list(self._clients.items()):
            try:
                if hasattr(client, "aclose"):
                    await client.aclose()
                elif hasattr(client, "close"):
                    res = client.close()
                    if asyncio.iscoroutine(res):
                        await res
            except Exception as exc:
                logger.warning("regional_redis_close_failed", data_region=region, error=str(exc))
        self._clients.clear()


_default_router: Optional[RegionalRedisRouter] = None


def init_regional_redis(
    *,
    default_url: Optional[str] = None,
    eu_url: Optional[str] = None,
    us_url: Optional[str] = None,
    env_prefix: str = "",
    decode_responses: bool = True,
    strict_eu: Optional[bool] = None,
) -> RegionalRedisRouter:
    """Initialize the process-wide regional async Redis router."""
    global _default_router
    _default_router = RegionalRedisRouter(
        default_url=default_url,
        eu_url=eu_url,
        us_url=us_url,
        env_prefix=env_prefix,
        decode_responses=decode_responses,
        strict_eu=strict_eu,
    )
    return _default_router


def get_regional_redis_router() -> RegionalRedisRouter:
    """Return the process-wide regional Redis router (auto-initializing from env if needed)."""
    global _default_router
    if _default_router is None:
        _default_router = RegionalRedisRouter()
    return _default_router


async def get_regional_redis(region: Optional[str] = None) -> Any:
    """Convenience helper returning the async Redis client for the active or requested region."""
    return await get_regional_redis_router().get_client(region=region)


async def close_regional_redis() -> None:
    """Close and reset the process-wide regional Redis router."""
    global _default_router
    if _default_router is not None:
        await _default_router.close_all()
        _default_router = None


def reset_regional_redis_router() -> None:
    """Clear the singleton router reference (for tests)."""
    global _default_router
    _default_router = None
