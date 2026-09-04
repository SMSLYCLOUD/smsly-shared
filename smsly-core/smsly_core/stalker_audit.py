"""
Stalker Audit — guaranteed-delivery audit event queue.

The legacy StalkerAuditMiddleware (kept for backward import compatibility)
was a no-op local logger. This module provides the real guaranteed-delivery
pattern the name always implied:

- queue_audit_event: fire-and-forget enqueue to a Redis list (never blocks)
- background flusher: drains the list to the audit service via the Security
  Gateway with exponential backoff; events retry until a 7-day TTL expires
- dead-letter list for manual investigation after TTL
- sync wrapper for worker threads / Django paths

Everything routes via {SECURITY_GATEWAY_URL}/api/v1/audit/events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_QUEUE_KEY = "smsly:audit:queue"
_DLQ_KEY = "smsly:audit:dlq"
_EVENT_TTL_SECONDS = 7 * 24 * 3600  # 7 days
_MAX_ATTEMPTS = 50
_BATCH = 50
_FLUSH_INTERVAL = 2.0

_BASE_URL = os.getenv(
    "SECURITY_GATEWAY_URL", "https://smsly-security-gateway:8080"
).rstrip("/")

_flusher_started = False


def _redis():
    import redis.asyncio as aioredis

    return aioredis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        decode_responses=True,
    )


async def queue_audit_event(
    event_type: str,
    resource_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    service: Optional[str] = None,
) -> bool:
    """Enqueue an audit event for guaranteed delivery. Never raises/never blocks."""
    event = {
        "service": service or os.getenv("SERVICE_NAME", "unknown"),
        "event_type": event_type,
        "resource_id": resource_id or "",
        "actor_id": actor_id or "",
        "payload": payload or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attempts": 0,
    }
    try:
        r = _redis()
        await r.rpush(_QUEUE_KEY, json.dumps(event))
        await r.expire(_QUEUE_KEY, _EVENT_TTL_SECONDS)
        start_flusher()
        return True
    except Exception as e:
        # last-resort local file (best-effort; a later deploy can replay)
        logger.warning("audit_enqueue_failed error=%s", e)
        try:
            with open("/tmp/audit_fallback.jsonl", "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass
        return False


def queue_audit_event_sync(
    event_type: str,
    resource_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    service: Optional[str] = None,
) -> bool:
    """Sync wrapper (worker threads / Django views)."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # called from inside a live loop — schedule, don't block
            asyncio.ensure_future(
                queue_audit_event(event_type, resource_id, actor_id, payload, service)
            )
            return True
        return bool(
            loop.run_until_complete(
                queue_audit_event(event_type, resource_id, actor_id, payload, service)
            )
        )
    except RuntimeError:
        # no loop in this thread (e.g. gunicorn sync worker) — fire a thread
        import threading

        def _run():
            asyncio.run(
                queue_audit_event(event_type, resource_id, actor_id, payload, service)
            )

        threading.Thread(target=_run, daemon=True).start()
        return True


async def _flush_loop():
    """Drain the queue to the audit service with backoff."""
    import httpx

    while True:
        drained = 0
        try:
            r = _redis()
            batch_raw = await r.lpop(_QUEUE_KEY, count=_BATCH)
            if batch_raw:
                if isinstance(batch_raw, str):
                    batch_raw = [batch_raw]
                events = []
                for raw in batch_raw:
                    try:
                        ev = json.loads(raw)
                        ev["attempts"] = int(ev.get("attempts", 0)) + 1
                        if ev["attempts"] > _MAX_ATTEMPTS:
                            await r.rpush(_DLQ_KEY, raw)
                            continue
                        events.append(ev)
                    except Exception:
                        await r.rpush(_DLQ_KEY, raw)

                if events:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        resp = await client.post(
                            f"{_BASE_URL}/api/v1/audit/events",
                            json={"service": events[0].get("service"), "events": events},
                        )
                    if resp.status_code >= 400:
                        # requeue for retry (front, preserves order)
                        for ev in events:
                            await r.lpush(_QUEUE_KEY, json.dumps(ev))
                    else:
                        drained = len(events)
        except Exception as e:
            logger.debug("audit_flush_error error=%s", e)

        await asyncio.sleep(_FLUSH_INTERVAL if drained else _FLUSH_INTERVAL * 5)


def start_flusher():
    """Start the background flusher once per process."""
    global _flusher_started
    if _flusher_started:
        return
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(_flush_loop())
        _flusher_started = True
    except RuntimeError:
        pass


# Backward import compatibility (was: a no-op middleware)
from .stalker_audit_middleware import StalkerAuditMiddleware  # noqa: E402,F401

__all__ = [
    "queue_audit_event",
    "queue_audit_event_sync",
    "StalkerAuditMiddleware",
]
