"""
Unified Database Module
=======================
Provides AsyncSessionLocal and get_db dependency for all services.
"""

from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import (
    create_async_engine as sa_create_async_engine,
    AsyncSession,
    async_sessionmaker,
    AsyncEngine,
)
from sqlalchemy.orm import DeclarativeBase
from contextlib import asynccontextmanager
import structlog

logger = structlog.get_logger(__name__)


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""
    pass


# Global engine and session factory - initialized by create_async_engine()
_engine: Optional[AsyncEngine] = None
_async_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def create_async_engine(
    database_url: str,
    pool_size: int = 10,
    max_overflow: int = 20,
    pool_pre_ping: bool = True,
    echo: bool = False,
) -> AsyncEngine:
    """
    Create and configure the async database engine.
    
    Call this once during application startup.
    
    Args:
        database_url: PostgreSQL async connection string (postgresql+asyncpg://...)
        pool_size: Connection pool size (default: 10)
        max_overflow: Max overflow connections (default: 20)
        pool_pre_ping: Enable connection health checks (default: True)
        echo: Log SQL statements (default: False)
    
    Returns:
        Configured AsyncEngine instance
    """
    global _engine, _async_session_factory
    
    _engine = sa_create_async_engine(
        database_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=pool_pre_ping,
        echo=echo,
    )
    
    _async_session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    
    logger.info("Database engine initialized", pool_size=pool_size)
    return _engine


def get_engine() -> AsyncEngine:
    """Get the current database engine."""
    if _engine is None:
        raise RuntimeError("Database engine not initialized. Call create_async_engine() first.")
    return _engine


def AsyncSessionLocal() -> async_sessionmaker[AsyncSession]:
    """
    Get the session factory for creating database sessions.
    
    Usage:
        async with AsyncSessionLocal()() as session:
            ...
    """
    if _async_session_factory is None:
        raise RuntimeError("Database not initialized. Call create_async_engine() first.")
    return _async_session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides a database session.
    
    Automatically commits on success and rolls back on exception.
    
    Usage:
        @app.get("/items")
        async def list_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    if _async_session_factory is None:
        raise RuntimeError("Database not initialized. Call create_async_engine() first.")
    
    async with _async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for getting a database session outside of FastAPI.
    
    Usage:
        async with get_session() as db:
            result = await db.execute(...)
    """
    if _async_session_factory is None:
        raise RuntimeError("Database not initialized. Call create_async_engine() first.")
    
    async with _async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def close_engine() -> None:
    """Close the database engine. Call during application shutdown."""
    global _engine, _async_session_factory
    
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None
        logger.info("Database engine closed")
