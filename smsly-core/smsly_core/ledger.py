import time
import logging
from enum import Enum
from typing import Optional, Dict, Any
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

class TraceStage(str, Enum):
    GATEWAY_IN = "gateway_in"
    PLATFORM_IN = "platform_in"
    BACKEND_IN = "backend_in"
    SERVICE_IN = "service_in"
    SERVICE_OUT = "service_out"
    AUDIT_FINAL = "audit_final"

class RequestLedger:
    """
    Client for the Distributed Request Ledger.
    Tracks the lifecycle of a request across all microservices using Redis.
    """
    def __init__(self, redis: Redis, ttl: int = 3600):
        self.redis = redis
        self.ttl = ttl

    def _key(self, request_id: str) -> str:
        return f"trace:{request_id}"

    async def init_trace(self, request_id: str, meta: Optional[Dict[str, Any]] = None):
        """
        Initialize the trace at the Gateway (Golden Copy creation).
        """
        key = self._key(request_id)
        payload = {
            "status": "PENDING",
            TraceStage.GATEWAY_IN.value: str(int(time.time())),
        }
        if meta:
            for k, v in meta.items():
                payload[f"meta:{k}"] = str(v)

        try:
            await self.redis.hset(key, mapping=payload)
            await self.redis.expire(key, self.ttl)
        except Exception as e:
            logger.error(f"Failed to init trace {request_id}: {e}")

    async def mark_stage(self, request_id: str, stage: TraceStage, **kwargs):
        """
        Mark a specific stage in the lifecycle.
        e.g., mark_stage(rid, TraceStage.SERVICE_OUT, provider_status="SENT")
        """
        key = self._key(request_id)
        payload = {
            stage.value: str(int(time.time()))
        }

        for k, v in kwargs.items():
            payload[k] = str(v)

        try:
            await self.redis.hset(key, mapping=payload)
            await self.redis.expire(key, self.ttl)
        except Exception as e:
            logger.error(f"Failed to mark stage {stage} for {request_id}: {e}")

    async def complete_trace(self, request_id: str):
        """
        Mark the trace as fully complete (Audit Log Confirmed).
        """
        key = self._key(request_id)
        try:
            await self.redis.hset(key, mapping={
                "status": "COMPLETE",
                TraceStage.AUDIT_FINAL.value: str(int(time.time()))
            })
            await self.redis.expire(key, self.ttl)
        except Exception as e:
            logger.error(f"Failed to complete trace {request_id}: {e}")

    async def fail_trace(self, request_id: str, error: str):
        """
        Mark the trace as failed.
        """
        key = self._key(request_id)
        try:
            await self.redis.hset(key, mapping={
                "status": "FAILED",
                "error": str(error),
                "failed_at": str(int(time.time()))
            })
        except Exception as e:
            logger.error(f"Failed to fail trace {request_id}: {e}")

    async def get_trace(self, request_id: str) -> Dict[str, str]:
        """
        Retrieve the full trace from Redis.
        Ensures all keys/values are decoded to strings.
        """
        key = self._key(request_id)
        try:
            raw_trace = await self.redis.hgetall(key)
            if not raw_trace:
                return {}
            # Decode bytes to strings if necessary
            return {
                k.decode('utf-8') if isinstance(k, bytes) else k:
                v.decode('utf-8') if isinstance(v, bytes) else v
                for k, v in raw_trace.items()
            }
        except Exception as e:
            logger.error(f"Failed to get trace {request_id}: {e}")
            return {}


class RequestLedgerSync:
    """
    Synchronous Client for the Distributed Request Ledger.
    For use in WSGI applications (Django).
    """
    def __init__(self, redis_client, ttl: int = 3600):
        self.redis = redis_client
        self.ttl = ttl

    def _key(self, request_id: str) -> str:
        return f"trace:{request_id}"

    def mark_stage(self, request_id: str, stage: TraceStage, **kwargs):
        """
        Mark a specific stage in the lifecycle (Sync).
        """
        key = self._key(request_id)
        payload = {
            stage.value: str(int(time.time()))
        }

        for k, v in kwargs.items():
            payload[k] = str(v)

        try:
            self.redis.hset(key, mapping=payload)
            self.redis.expire(key, self.ttl)
        except Exception as e:
            logger.error(f"Failed to mark stage {stage} for {request_id}: {e}")
