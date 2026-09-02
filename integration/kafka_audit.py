"""Kafka (Redpanda) audit bus producer — shared across services.

Drop-in replacement for Redis Streams. Same `publish(event_type, actor_id, ...)`
contract as RedisStreamAuditBus; selected via env:

    AUDIT_BUS=redis-stream   (default) -> XADD smsly:audit
    AUDIT_BUS=kafka          -> producer.send(SMSLY_AUDIT_TOPIC)
    AUDIT_BUS=http           -> legacy POST fallback (integration.audit_client)

Why Kafka: throughput, partition-by-tenant for ordering, retention
independent of Redis memory. Redpanda is the single-binary Kafka-API
compatible server (no JVM/Zookeeper), simple to deploy in Grid.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Optional

logger = logging.getLogger("audit-bus-kafka")

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "localhost:9092").split(",")
SMSLY_AUDIT_TOPIC = os.getenv("SMSLY_AUDIT_TOPIC", "smsly.audit")
KAFKA_PRODUCER_LINGER_MS = int(os.getenv("KAFKA_PRODUCER_LINGER_MS", "50"))
KAFKA_PRODUCER_BATCH_SIZE = int(os.getenv("KAFKA_PRODUCER_BATCH_SIZE", "16384"))
KAFKA_PRODUCER_REQUEST_TIMEOUT_MS = int(os.getenv("KAFKA_PRODUCER_REQUEST_TIMEOUT_MS", "5000"))


class KafkaAuditBus:
    """Kafka/Redpanda producer — at-least-once via local buffer on send failures.

    fire-and-forget with a bounded in-memory queue for the case where the
    broker is unreachable. Mirrors RedisStreamAuditBus semantics.
    """

    def __init__(self, brokers: Optional[list[str]] = None, topic: Optional[str] = None):
        self._brokers = brokers or KAFKA_BROKERS
        self._topic = topic or SMSLY_AUDIT_TOPIC
        self._producer = None
        self._lock = asyncio.Lock()
        self._pending: list[tuple[str, dict]] = []
        self._started = False

    async def _ensure_producer(self):
        if self._producer is not None:
            return self._producer
        async with self._lock:
            if self._producer is not None:
                return self._producer
            try:
                from aiokafka import AIOKafkaProducer
                self._producer = AIOKafkaProducer(
                    bootstrap_servers=self._brokers,
                    linger_ms=KAFKA_PRODUCER_LINGER_MS,
                    max_batch_size=KAFKA_PRODUCER_BATCH_SIZE,
                    request_timeout_ms=KAFKA_PRODUCER_REQUEST_TIMEOUT_MS,
                    # In sync with existing chain: events carry a key for
                    # per-tenant ordering/partition affinity.
                    key_serializer=lambda k: k.encode("utf-8") if k else None,
                    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                )
                await self._producer.start()
                self._started = True
                logger.info("kafka_producer_started brokers=%s topic=%s", self._brokers, self._topic)
            except Exception as e:
                logger.warning("kafka_producer_unavailable err=%s", str(e))
                self._producer = None
        return self._producer

    async def start(self):
        await self._ensure_producer()
        # Drain any events buffered while the broker was down
        if self._pending and self._producer:
            for event_type, payload in self._pending[:]:
                await self._do_send(event_type, payload)
                self._pending.remove((event_type, payload))
            logger.info("audit_bus_backlog_drained count=%d", len(self._pending))

    async def stop(self):
        if self._producer:
            try:
                await self._producer.stop()
            except Exception:
                pass
            self._producer = None
            logger.info("kafka_producer_stopped")

    async def _do_send(self, event_type: str, payload: dict):
        # Encode as JSON in the value; key by tenant_id if present so
        # all events for one tenant are ordered on the same partition
        key = payload.get("tenant_id") or payload.get("service") or event_type
        await self._producer.send_and_wait(
            topic=self._topic,
            key=key,
            value={
                "event_type": event_type,
                "ts": time.time(),
                "payload": payload,
            },
        )

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
        """Publish one audit event. Returns True if accepted by the broker.

        On any send failure, falls back to the local bounded in-memory queue
        (drained on next successful start) so the caller's request still
        records the intent — better than dropping the event entirely.
        """
        payload = {
            "actor_id": actor_id,
            "resource_id": resource_id,
            "category": category,
            "outcome": outcome,
            "severity": severity,
            "metadata": metadata or {},
            **extra,
        }
        producer = await self._ensure_producer()
        if producer is None:
            if len(self._pending) < 10_000:
                self._pending.append((event_type, payload))
                return False
            return False
        try:
            await self._do_send(event_type, payload)
            return True
        except Exception as e:
            logger.warning("kafka_producer_send_failed err=%s", str(e))
            if len(self._pending) < 10_000:
                self._pending.append((event_type, payload))
            return False
