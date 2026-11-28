"""
Unified Multi-Region Database Module
====================================
Provides AsyncSessionLocal and get_db dependency for all FastAPI services with
transparent EU GDPR / Geo-Residency database routing.

Backward-compatible with single-DB callers:
- ``create_async_engine(database_url, ...)`` initializes the ``default`` engine and
  automatically registers ``eu`` / ``us`` regional engines when ``DATABASE_URL_EU``
  (or ``EU_DATABASE_URL``) / ``DATABASE_URL_US`` are present in the environment.
- ``get_db()``, ``get_session()``, ``get_engine()``, and ``AsyncSessionLocal()``
  automatically route to the active ContextVar data region (set by
  ``DataRegionMiddleware`` from gateway-attested ``X-Trulay-Data-Region``).
- When ``EU_RESIDENCY_STRICT=true``, requests scoped to ``eu`` fail closed with
  ``DataResidencyError`` if no EU database is registered.
"""
from __future__ import annotations

import os
import ssl
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, Optional

import structlog
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine as sa_create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool

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


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""
    pass


# Backward-compatible primary references + multi-region registries
_engine: Optional[AsyncEngine] = None
_async_session_factory: Optional[async_sessionmaker[AsyncSession]] = None
_engines: Dict[str, AsyncEngine] = {}
_session_factories: Dict[str, async_sessionmaker[AsyncSession]] = {}
_strict_eu_override: Optional[bool] = None
_default_env_prefix: str = ""
_default_pool_config: Dict[str, Any] = {
    "pool_size": 10,
    "max_overflow": 20,
    "pool_pre_ping": True,
    "echo": False,
}


def prepare_asyncpg_url_and_ssl(raw_url: str) -> tuple[str, Optional[object]]:
    """Translate libpq ``postgresql://`` and ``?sslmode=`` query params for asyncpg."""
    normalized = raw_url.strip()
    if normalized.startswith("postgresql://"):
        normalized = normalized.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif normalized.startswith("postgres://"):
        normalized = normalized.replace("postgres://", "postgresql+asyncpg://", 1)

    if normalized.lower().startswith("sqlite"):
        return normalized, None

    parsed = make_url(normalized)
    query = dict(parsed.query)
    raw_mode = query.pop("sslmode", None)
    if isinstance(raw_mode, (list, tuple)):
        raw_mode = raw_mode[-1] if raw_mode else None

    ssl_arg: Optional[object] = None
    if raw_mode is not None:
        mode = str(raw_mode).strip().lower()
        if mode == "disable":
            ssl_arg = False
        elif mode in ("verify-ca", "verify-full"):
            ssl_arg = ssl.create_default_context()
        elif mode in ("require", "prefer", "allow"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssl_arg = ctx

    clean_url = parsed.set(query=query).render_as_string(hide_password=False)
    return clean_url, ssl_arg


def _build_engine(
    database_url: str,
    *,
    pool_size: int = 10,
    max_overflow: int = 20,
    pool_pre_ping: bool = True,
    echo: bool = False,
) -> AsyncEngine:
    clean_url, asyncpg_ssl = prepare_asyncpg_url_and_ssl(database_url)
    if clean_url.startswith("sqlite"):
        kwargs: Dict[str, Any] = {
            "echo": echo,
            "connect_args": {"check_same_thread": False},
        }
        if ":memory:" in clean_url:
            kwargs["poolclass"] = StaticPool
        return sa_create_async_engine(clean_url, **kwargs)

    connect_args: Dict[str, Any] = {
        "statement_cache_size": 0,
        "prepared_statement_cache_size": 0,
    }
    if asyncpg_ssl is not None:
        connect_args["ssl"] = asyncpg_ssl
    return sa_create_async_engine(
        clean_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=pool_pre_ping,
        echo=echo,
        connect_args=connect_args,
    )


def _discover_regional_url(region: str, env_prefix: str = "") -> Optional[str]:
    pfx = f"{env_prefix.strip('_').upper()}_" if env_prefix else ""
    norm = normalize_data_region(region)
    if norm == REGION_DEFAULT:
        candidates = (
            f"{pfx}DATABASE_URL" if pfx else "",
            "DATABASE_URL",
        )
    else:
        tag = region_env_suffix(norm)
        candidates = (
            f"{pfx}DATABASE_URL_{tag}" if pfx else "",
            f"{pfx}{tag}_DATABASE_URL" if pfx else "",
            f"DATABASE_URL_{tag}",
            f"{tag}_DATABASE_URL",
        )
    for var in candidates:
        if not var:
            continue
        val = os.getenv(var, "").strip()
        if val:
            return val
    return None


def register_regional_engine(
    region: str,
    database_url: str,
    *,
    pool_size: int = 10,
    max_overflow: int = 20,
    pool_pre_ping: bool = True,
    echo: bool = False,
) -> AsyncEngine:
    """Register (or replace) an async SQLAlchemy engine for a specific residency region."""
    global _engine, _async_session_factory

    norm = normalize_data_region(region)
    eng = _build_engine(
        database_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=pool_pre_ping,
        echo=echo,
    )
    factory = async_sessionmaker(
        eng,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    _engines[norm] = eng
    _session_factories[norm] = factory

    if norm == REGION_DEFAULT:
        _engine = eng
        _async_session_factory = factory

    logger.info("Regional database engine registered", data_region=norm, pool_size=pool_size)
    return eng


def create_async_engine(
    database_url: str,
    pool_size: int = 10,
    max_overflow: int = 20,
    pool_pre_ping: bool = True,
    echo: bool = False,
    *,
    eu_database_url: Optional[str] = None,
    us_database_url: Optional[str] = None,
    env_prefix: str = "",
    strict_eu: Optional[bool] = None,
) -> AsyncEngine:
    """Create and configure the primary async database engine plus any configured regional engines."""
    global _strict_eu_override, _default_env_prefix, _default_pool_config
    _strict_eu_override = strict_eu
    _default_env_prefix = env_prefix
    _default_pool_config = {
        "pool_size": pool_size,
        "max_overflow": max_overflow,
        "pool_pre_ping": pool_pre_ping,
        "echo": echo,
    }

    primary = register_regional_engine(
        REGION_DEFAULT,
        database_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=pool_pre_ping,
        echo=echo,
    )

    resolved_eu = eu_database_url or _discover_regional_url(REGION_EU, env_prefix=env_prefix)
    if resolved_eu:
        register_regional_engine(
            REGION_EU,
            resolved_eu,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=pool_pre_ping,
            echo=echo,
        )

    resolved_us = us_database_url or _discover_regional_url(REGION_US, env_prefix=env_prefix)
    if resolved_us:
        register_regional_engine(
            REGION_US,
            resolved_us,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=pool_pre_ping,
            echo=echo,
        )

    # Auto-discover any custom admin-defined regional DSNs (DATA_RESIDENCY_REGIONS or DATABASE_URL_<TAG>)
    extra_regions: list[str] = []
    for raw in os.getenv("DATA_RESIDENCY_REGIONS", "").split(","):
        slug = normalize_data_region(raw)
        if slug not in (REGION_DEFAULT, REGION_EU, REGION_US) and slug not in extra_regions:
            extra_regions.append(slug)
    env_prefix_tag = f"{env_prefix.upper().strip('_')}_" if env_prefix else ""
    dsn_prefix = f"{env_prefix_tag}DATABASE_URL_"
    for env_k in os.environ.keys():
        if env_k.startswith(dsn_prefix):
            tag = env_k[len(dsn_prefix):].strip().lower().replace("_", "-")
            if tag and tag not in ("default", "primary", "replica", "read", REGION_EU, REGION_US):
                norm_tag = normalize_data_region(tag)
                if norm_tag != REGION_DEFAULT and norm_tag not in extra_regions:
                    extra_regions.append(norm_tag)
    for custom_region in extra_regions:
        resolved_custom = _discover_regional_url(custom_region, env_prefix=env_prefix)
        if resolved_custom:
            register_regional_engine(
                custom_region,
                resolved_custom,
                pool_size=pool_size,
                max_overflow=max_overflow,
                pool_pre_ping=pool_pre_ping,
                echo=echo,
            )

    return primary


def init_regional_engines(
    default_url: Optional[str] = None,
    *,
    eu_url: Optional[str] = None,
    us_url: Optional[str] = None,
    env_prefix: str = "",
    pool_size: int = 10,
    max_overflow: int = 20,
    pool_pre_ping: bool = True,
    echo: bool = False,
    strict_eu: Optional[bool] = None,
) -> Dict[str, AsyncEngine]:
    """Initialize default + regional engines from explicit URLs or environment variables."""
    resolved_default = default_url or _discover_regional_url(REGION_DEFAULT, env_prefix=env_prefix)
    if not resolved_default:
        raise RuntimeError("DATABASE_URL is required to initialize regional database engines.")
    create_async_engine(
        resolved_default,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=pool_pre_ping,
        echo=echo,
        eu_database_url=eu_url,
        us_database_url=us_url,
        env_prefix=env_prefix,
        strict_eu=strict_eu,
    )
    return dict(_engines)


def _resolve_target_region(region: Optional[str] = None) -> str:
    target = normalize_data_region(region if region is not None else get_data_region())
    if target in _engines:
        return target

    if target != REGION_DEFAULT:
        discovered = _discover_regional_url(target, env_prefix=_default_env_prefix)
        if discovered:
            register_regional_engine(target, discovered, **_default_pool_config)
            return target

    strict_eu = _strict_eu_override if _strict_eu_override is not None else is_eu_residency_strict()
    is_strict = (target == REGION_EU and strict_eu) or (target != REGION_EU and is_region_strict(target))
    if is_strict:
        suffix = region_env_suffix(target)
        raise DataResidencyError(
            f"Regional database store (DATABASE_URL_{suffix}) is required under strict residency enforcement.",
            data_region=target,
            store_type="database",
        )

    if REGION_DEFAULT in _engines:
        if target == REGION_EU:
            logger.warning("eu_database_unconfigured_falling_back_to_default", data_region=target)
        return REGION_DEFAULT

    raise RuntimeError("Database engine not initialized. Call create_async_engine() first.")


def get_engine(region: Optional[str] = None) -> AsyncEngine:
    """Get the async SQLAlchemy engine for the requested or active ContextVar region."""
    resolved = _resolve_target_region(region)
    return _engines[resolved]


def get_all_engines() -> Dict[str, AsyncEngine]:
    """Return a copy of all registered regional engines."""
    return dict(_engines)


def AsyncSessionLocal(region: Optional[str] = None) -> async_sessionmaker[AsyncSession]:
    """Get the session factory for the requested or active ContextVar region."""
    resolved = _resolve_target_region(region)
    return _session_factories[resolved]


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a session bound to the active request's data region."""
    factory = AsyncSessionLocal()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def get_session(region: Optional[str] = None) -> AsyncGenerator[AsyncSession, None]:
    """Context manager for obtaining a regional database session outside FastAPI."""
    factory = AsyncSessionLocal(region=region)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_tables_all_regions(
    metadata: Any,
    regions: Optional[tuple[str, ...] | list[str]] = None,
) -> Dict[str, bool]:
    """Run ``metadata.create_all`` against every registered (or explicitly requested) regional engine."""
    if regions:
        for r in regions:
            norm = normalize_data_region(r)
            if norm not in _engines and norm != REGION_DEFAULT:
                discovered = _discover_regional_url(norm, env_prefix=_default_env_prefix)
                if discovered:
                    register_regional_engine(norm, discovered, **_default_pool_config)
    results: Dict[str, bool] = {}
    for region, eng in list(_engines.items()):
        async with eng.begin() as conn:
            await conn.run_sync(metadata.create_all)
        results[region] = True
    return results


async def check_all_databases_health() -> Dict[str, bool]:
    """Execute ``SELECT 1`` across every registered regional database."""
    health: Dict[str, bool] = {}
    for region, factory in list(_session_factories.items()):
        try:
            async with factory() as session:
                await session.execute(text("SELECT 1"))
            health[region] = True
        except Exception as exc:
            logger.error("regional_database_health_failed", data_region=region, error=str(exc))
            health[region] = False
    return health


async def close_engine() -> None:
    """Backwards-compatible alias for close_all_engines()."""
    await close_all_engines()


async def close_db() -> None:
    """Close and dispose all registered regional database engines."""
    await close_all_engines()


async def close_all_engines() -> None:
    """Dispose every registered regional engine and clear registry state."""
    global _engine, _async_session_factory, _strict_eu_override, _default_env_prefix, _default_pool_config

    for region, eng in list(_engines.items()):
        try:
            await eng.dispose()
            logger.info("Regional database engine disposed", data_region=region)
        except Exception as exc:
            logger.warning("Regional database dispose failed", data_region=region, error=str(exc))
    _engines.clear()
    _session_factories.clear()
    _engine = None
    _async_session_factory = None
    _strict_eu_override = None
    _default_env_prefix = ""
    _default_pool_config = {
        "pool_size": 10,
        "max_overflow": 20,
        "pool_pre_ping": True,
        "echo": False,
    }
