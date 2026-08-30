"""Redis Streams audit bus — shared producer for all services.

Publishes audit events to a Redis Stream (default: smsly:audit) instead of
per-service HTTP POST to the Audit Service. One consumer group in the Audit
Service (XREADGROUP -> audit_events table -> hash chain -> XACK) replaces
9 per-service retry/fallback implementations.

Transport is env-switchable so Kafka/Redpanda can replace Redis Streams later
with the same producer interface:

    AUDIT_BUS=redis-stream   (default) -> XADD smsly:audit
    AUDIT_BUS=http           (legacy)  -> POST audit-service (old path, fallback)

Usage (identical to existing audit client):
    from integration.stream_audit import get_audit_bus
    bus = await get_audit_bus()
    await bus.publish(event_type="sms.sent", actor_id="u1", category="messaging")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Optional

logger = logging.getLogger("audit-bus")

STREAM_KEY = os.getenv("AUDIT_STREAM", "smsly:audit")
MAX_STREAM_LEN = int(os.getenv("AUDIT_STREAM_MAXLEN", "1000000"))  # ~1M events retained
BUS_MODE = os.getenv("AUDIT_BUS", "redis-stream")  # redis-stream | http


class RedisStreamAuditBus:
    """Producer — XADD events to the shared audit stream.

    Fire-and-forget with maxlen trimming; no client-side retry needed because
    the stream itself is the durable buffer (consumer is XREADGROUP-driven).
    """

    def __init__(self, redis_url: Optional[str] = None):
        self._redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._redis = None
        self._lock = asyncio.Lock()
        self._pending: list[tuple[str, dict]] = []  # buffer if redis down at import
        self._started = False

    async def _ensure_redis(self):
        if self._redis is not None:
            return self._redis
        async with self._lock:
            if self._redis is not None:
                return self._redis
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(self._redis_url, decode_responses=True)
                await self._redis.ping()
                self._started = True
            except Exception as e:
                logger.warning("audit_bus_redis_unavailable", error=str(e))
                self._redis = None
        return self._redis

    async def start(self):
        await self._ensure_redis()
        # Flush any events buffered while redis was down
        if self._pending and self._redis:
            for event_type, payload in self._pending[:]:
                await self._do_xadd(event_type, payload)
                self._pending.remove((event_type, payload))
        logger.info("audit_bus_started", stream=STREAM_KEY, mode=BUS_MODE)

    async def stop(self):
        if self._redis:
            try:
                await self._redis.aclose()
            except Exception:
                pass
            self._redis = None

    async def _do_xadd(self, event_type: str, payload: dict):
        entry = {
            "event_type": event_type,
            "ts": str(time.time()),
            "payload": json.dumps(payload, default=str),
        }
        await self._redis.xadd(STREAM_KEY, entry, maxlen=MAX_STREAM_LEN, approximate=True)

    async def publish(
        self,
        event_type: str,
        actor_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        category: Optional[str] = None,
        outcome: Optional[str] = None,
        severity: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        **extra,
    ) -> bool:
        """Publish one event to the stream. Returns True if accepted by redis."""
        payload = {
            "actor_id": actor_id,
            "resource_id": resource_id,
            "category": category,
            "outcome": outcome,
            "severity": severity,
            "metadata": metadata or {},
            **extra,
        }
        r = await self._ensure_redis()
        if r is None:
            # Buffer (bounded) — consumer drain later; drop if over 10k
            if len(self._pending) < 10_000:
                self._pending.append((event_type, payload))
                return False
            return False
        try:
            await self._do_xadd(event_type, payload)
            return True
        except Exception as e:
            logger.warning("audit_bus_xadd_failed", error=str(e))
            if len(self._pending) < 10_000:
                self._pending.append((event_type, payload))
            return False


# --- Legacy HTTP fallback (keeps old audit client path when AUDIT_BUS=http) ---
class HttpAuditFallback:
    """Delegates to the existing integration.audit_client for AUDIT_BUS=http."""

    def __init__(self):
        from integration.audit_client import AuditClient
        self._client = AuditClient()

    async def start(self):
        await self._client.start()

    async def stop(self):
        await self._client.stop()

    async def publish(self, **kwargs) -> bool:
        return bool(await self._client.log(**kwargs))


_bus: Optional[RedisStreamAuditBus] = None


async def get_audit_bus():
    """Get the singleton audit bus (stream or http based on AUDIT_BUS)."""
    global _bus
    if BUS_MODE == "http":
        # http mode uses its own singleton inside audit_client
        from integration.audit_client import get_audit_client
        return get_audit_client()
    if _bus is None:
        _bus = RedisStreamAuditBus()
        await _bus.start()
    return _bus
