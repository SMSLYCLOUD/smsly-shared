"""Resilient DB/Redis boot helper — shared across services.

Solves the Grid cold-boot race: workers start before the Postgres/Redis
addon DNS records are resolvable. Without this, `create_all`/`ping` at
lifespan raises socket.gaierror [Errno -2/-3] and the worker dies, leaving
deploys STAGED with half the workers alive.

Usage (FastAPI lifespan):

    from integration.resilient_boot import wait_for_db, wait_for_redis

    db_ok = await wait_for_db(engine, attempts=12, delay=10)
    if db_ok:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    redis = await wait_for_redis(redis_url, attempts=6, delay=5)

Works for any SQLAlchemy async engine (asyncpg driver) and redis.asyncio.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger("resilient-boot")

# Error substrings that indicate transient infra (retry-able), not schema bugs.
_TRANSIENT_MARKERS = (
    "Name or service not known",       # DNS resolution (gaierror -2)
    "name resolution",                 # DNS resolution (gaierror -3)
    "Temporary failure in name",       # gaierror -3 full text
    "Connection refused",              # service up but not listening yet
    "Connection reset",                 # listener restarting
    "ConnectionResetError",
    "TimeoutError",                     # network blackhole
    "timed out",
    "gaierror",
    "SSL: CONNECTION",                 # TLS handshake cut mid-boot
    "the database system is starting",  # Postgres recovery mode
    "server is in recovery",
    "too many connections",            # pool exhausted by sibling workers
)


def _is_transient(exc: Exception) -> bool:
    msg = str(exc)
    return any(marker in msg for marker in _TRANSIENT_MARKERS)


async def wait_for_db(engine, *, attempts: int = 12, delay: float = 10.0, purpose: str = "db") -> bool:
    """Wait for DB reachability. Returns True when ready, False if exhausted.

    `attempts` * `delay` seconds of grace (default 12*10 = 2 minutes) —
    comfortably covers Grid addon DNS propagation (~30-60s).
    """
    from sqlalchemy import text
    for attempt in range(1, attempts + 1):
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            if attempt > 1:
                logger.info("%s_recovered attempt=%d", purpose, attempt)
            return True
        except Exception as e:
            if _is_transient(e):
                logger.warning(
                    "%s_not_ready attempt=%d/%d retry_in=%.0fs err=%s",
                    purpose, attempt, attempts, delay, str(e)[:120],
                )
                await asyncio.sleep(delay)
                continue
            # Non-transient (auth failure, bad DSN, missing table = programming
            # error) — raise immediately, retrying is pointless
            raise
    logger.error("%s_unavailable_after %d attempts — degrading", purpose, attempts)
    return False


async def wait_for_redis(
    redis_url: str,
    *,
    attempts: int = 6,
    delay: float = 5.0,
) -> Optional[object]:
    """Wait for Redis reachability. Returns the connected client or None."""
    try:
        import redis.asyncio as aioredis
    except ImportError:
        logger.warning("redis_not_installed")
        return None
    for attempt in range(1, attempts + 1):
        try:
            client = aioredis.from_url(redis_url, decode_responses=True)
            await client.ping()
            if attempt > 1:
                logger.info("redis_recovered attempt=%d", attempt)
            return client
        except Exception as e:
            if _is_transient(e):
                logger.warning(
                    "redis_not_ready attempt=%d/%d retry_in=%.0fs err=%s",
                    attempt, attempts, delay, str(e)[:120],
                )
                await asyncio.sleep(delay)
                continue
            logger.warning("redis_init_failed err=%s", str(e)[:120])
            return None
    logger.error("redis_unavailable_after %d attempts — in-memory mode", attempts)
    return None
