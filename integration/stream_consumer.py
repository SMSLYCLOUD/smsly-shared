"""Redis Streams audit consumer — runs inside Audit Log Service.

Single consumer group (XREADGROUP) draining the smsly:audit stream into the
audit_events table + hash chain. Replaces 9 per-service HTTP POST paths.

Deployed in AUDIT service only (app/main.py lifespan starts `stream_consumer`).
Other services only produce (integration/stream_audit.py).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Optional

logger = logging.getLogger("audit-stream-consumer")

STREAM_KEY = os.getenv("AUDIT_STREAM", "smsly:audit")
GROUP = os.getenv("AUDIT_STREAM_GROUP", "audit-writer")
CONSUMER_NAME = os.getenv("AUDIT_STREAM_CONSUMER", f"audit-{os.getpid()}")
BATCH = int(os.getenv("AUDIT_STREAM_BATCH", "50"))
BLOCK_MS = int(os.getenv("AUDIT_STREAM_BLOCK_MS", "2000"))
CLAIM_IDLE_MS = int(os.getenv("AUDIT_STREAM_CLAIM_IDLE", "60000"))  # reclaim stuck after 60s


class AuditStreamConsumer:
    def __init__(self, db_session_factory, redis_url: Optional[str] = None):
        self._session_factory = db_session_factory  # AsyncSessionLocal from app.main
        self._redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._redis = None
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._processed = 0
        self._errors = 0

    async def _ensure(self):
        if self._redis is not None:
            return True
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(self._redis_url, decode_responses=True)
            await self._redis.ping()
        except Exception as e:
            logger.warning("audit_consumer_redis_unavailable", error=str(e))
            self._redis = None
            return False
        return True

    async def _ensure_group(self):
        """Create the consumer group at '0' so we consume from stream start."""
        try:
            await self._redis.xgroup_create(STREAM_KEY, GROUP, id="0", mkstream=True)
        except Exception as e:
            if "BUSYGROUP" not in str(e):
                logger.warning("xgroup_create failed (non-fatal)", error=str(e))

    async def start(self):
        if not await self._ensure():
            logger.warning("audit_consumer_deferred (redis down at boot)")
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        if self._redis:
            await self._redis.aclose()

    async def _run(self):
        while self._running:
            try:
                if not await self._ensure():
                    await asyncio.sleep(5)
                    continue
                await self._ensure_group()

                # 1) Reclaim messages stuck with idle consumers
                try:
                    claimed = await self._redis.xautoclaim(
                        STREAM_KEY, GROUP, CONSUMER_NAME, min_idle_time=CLAIM_IDLE_MS, count=BATCH
                    )
                    if claimed and claimed[0]:
                        await self._process(claimed[0])
                except Exception:
                    pass

                # 2) Read new messages
                messages = await self._redis.xreadgroup(
                    GROUP, CONSUMER_NAME, {STREAM_KEY: ">"}, count=BATCH, block=BLOCK_MS
                )
                if messages:
                    for _stream, entries in messages:
                        await self._process(entries)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                self._errors += 1
                logger.warning("audit_consumer_cycle_failed", error=str(e))
                await asyncio.sleep(2)

    async def _process(self, entries):
        """Write batch to audit_events + hash chain, then XACK."""
        from .service import AuditService  # audit service internals

        for msg_id, fields in entries:
            try:
                payload = json.loads(fields.get("payload", "{}"))
                async with self._session_factory() as session:
                    service = AuditService(session)
                    event = {
                        "service": fields.get("service", payload.get("service", "unknown")),
                        "event_type": fields.get("event_type", payload.get("event_type", "unknown")),
                        "actor_id": payload.get("actor_id"),
                        "action": payload.get("event_type", "unknown"),
                        "payload": payload,
                        "category": payload.get("category"),
                        "severity": payload.get("severity", "info"),
                        "outcome": payload.get("outcome", "success"),
                    }
                    # create_event handles hash-chain + risk scoring + alerts
                    await service.create_event(event)
                await self._redis.xack(STREAM_KEY, GROUP, msg_id)
                self._processed += 1
            except Exception as e:
                # NOT acked -> stays PEL, reclaimed later by xautoclaim
                self._errors += 1
                logger.warning("audit_event_write_failed", msg_id=msg_id, error=str(e))

    @property
    def stats(self):
        return {"processed": self._processed, "errors": self._errors}

    async def health_check(self) -> dict:
        """Probe bus health: Redis group + backlog, or Kafka consumer lag.

        Returns dict with at minimum {healthy: bool, mode: str, processed: int, errors: int}.
        Callers (the audit service /ready route) translate this into 200/503.
        """
        result = {
            "healthy": True,
            "mode": os.getenv("AUDIT_BUS", "redis-stream"),
            "processed": self._processed,
            "errors": self._errors,
        }
        if self._redis is None:
            result["healthy"] = False
            result["redis"] = "disconnected"
            return result
        try:
            # 1. Verify the consumer group exists (XINFO GROUPS) — if it
            # doesn't, the consumer has never read anything and we silently
            # never committed a cursor, which means a Redis restart loses
            # position. Auto-create on miss (idempotent).
            groups = await self._redis.xinfo_groups(STREAM_KEY)
            group_names = {g["name"] for g in groups} if isinstance(groups, list) else set()
            if GROUP not in group_names:
                await self._ensure_group()
                result["consumer_group_recreated"] = True
            # 2. Pending entries: stream length minus group's last-delivered ID
            stream_len = await self._redis.xlen(STREAM_KEY)
            info = await self._redis.xinfo_groups(STREAM_KEY, GROUP)
            group = info[0] if info else {}
            lag = max(0, stream_len - (group.get("last-delivered-id") and stream_len or 0))
            # Simpler lag: PEL size
            pel = group.get("pending", 0)
            result["stream_length"] = stream_len
            result["pending_entries"] = pel
            result["consumer"] = CONSUMER_NAME
            if pel > 10_000:  # arbitrary alert threshold
                result["healthy"] = False
                result["lag_alert"] = f"pending={pel} exceeds 10k"
        except Exception as e:
            result["healthy"] = False
            result["redis_error"] = str(e)[:120]
        return result
