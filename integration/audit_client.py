"""
Async gRPC Audit Client for Python Services.

Provides a resilient, batched audit client that talks directly to the
Audit Service via tonic gRPC. Replaces the per-service HTTP clients
with a single shared implementation.

Features:
- Client-streaming batch ingestion (amortized latency)
- Circuit breaker with exponential backoff
- Local fallback buffer on transient failures
- Configurable fail-closed / fail-open per event
- HMAC request signing (for backward-compat HTTP proxy path)

Usage:
    from audit.integration.audit_client import get_audit_client

    client = get_audit_client()
    await client.start()

    await client.log(
        event_type="sms.sent",
        resource_id="msg_123",
        actor_id="user_456",
        category="messaging",
    )

    # Or batch manually
    await client.flush()

    # On shutdown
    await client.stop()
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional

import httpx

from .events import (
    AuditEvent,
    AuditEventBatch,
    Category,
    Outcome,
    Severity,
    make_event,
)

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

# Primary: gRPC via tonic (direct to Audit Service)
GRPC_TARGET = os.getenv("AUDIT_GRPC_TARGET", "localhost:8005")

# Fallback: HTTP via Gateway (backward compat)
GATEWAY_URL = os.getenv("SECURITY_GATEWAY_URL", "http://localhost:8000")
AUDIT_HTTP_PATH = os.getenv("AUDIT_HTTP_PATH", "/api/v1/audit/events")

SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown-service")
SERVICE_SECRET = os.getenv("SERVICE_SECRET", "")

# Tuning - tolerant parsing (Grid may inject false/empty for unset numerics)
def _env_int(key, default):
    try:
        return int(str(os.getenv(key, default)).strip() or default)
    except (ValueError, TypeError):
        return default

def _env_float(key, default):
    try:
        return float(str(os.getenv(key, default)).strip() or default)
    except (ValueError, TypeError):
        return default

BATCH_SIZE = _env_int("AUDIT_BATCH_SIZE", 50)
FLUSH_INTERVAL_S = _env_float("AUDIT_FLUSH_INTERVAL", 2.0)
BATCH_TIMEOUT_S = _env_float("AUDIT_BATCH_TIMEOUT", 5.0)
HTTP_TIMEOUT_S = _env_float("AUDIT_HTTP_TIMEOUT", 3.0)
CIRCUIT_FAILURE_THRESHOLD = _env_int("AUDIT_CIRCUIT_THRESHOLD", 5)
CIRCUIT_RECOVERY_S = _env_float("AUDIT_CIRCUIT_RECOVERY", 30.0)

# Fail-closed env (production default: true)
# AUDIT_FAIL_CLOSED overrides per-service; falls back to environment-based default
_fail_closed_override = os.getenv("AUDIT_FAIL_CLOSED", "")
if _fail_closed_override:
    FAIL_CLOSED_DEFAULT = _fail_closed_override.lower() == "true"
else:
    _env = os.getenv("ENVIRONMENT", "development").lower()
    FAIL_CLOSED_DEFAULT = _env in ("production", "prod", "staging")

# Fallback buffer — Grid's gVisor is read-only at /var/log, so auto-fallback to /app/tmp if needed


def _resolve_fallback_dir():
    candidates = []
    raw = os.getenv("AUDIT_FALLBACK_DIR", "/app/tmp/audit_fallback")
    if raw.startswith("/var/log"):
        raw = "/app/tmp/audit_fallback"
    candidates.append(Path(raw))
    candidates.append(Path("/app/tmp/audit_fallback"))
    candidates.append(Path(tempfile.gettempdir()) / "smsly_audit_fallback")
    for p in candidates:
        try:
            p.mkdir(parents=True, exist_ok=True)
            test = p / ".writetest"
            test.touch(exist_ok=True)
            test.unlink(missing_ok=True)
            return p
        except Exception:
            continue
    return candidates[-1]


FALLBACK_DIR = _resolve_fallback_dir()
FALLBACK_FILE = FALLBACK_DIR / "audit_fallback.jsonl"
FALLBACK_MAX_BYTES = _env_int("AUDIT_FALLBACK_MAX_MB", 50) * 1024 * 1024


# ============================================================================
# Circuit Breaker
# ============================================================================

class CircuitBreaker:
    """Simple state-machine circuit breaker."""

    def __init__(
        self,
        failure_threshold: int = CIRCUIT_FAILURE_THRESHOLD,
        recovery_timeout: float = CIRCUIT_RECOVERY_S,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures = 0
        self._last_failure = 0.0
        self._state = "closed"  # closed | open | half_open

    @property
    def is_open(self) -> bool:
        if self._state == "closed":
            return False
        if self._state == "open":
            if time.monotonic() - self._last_failure >= self.recovery_timeout:
                self._state = "half_open"
                return False
            return True
        return False  # half_open — allow one attempt

    def record_success(self):
        self._failures = 0
        self._state = "closed"

    def record_failure(self):
        self._failures += 1
        self._last_failure = time.monotonic()
        if self._failures >= self.failure_threshold:
            self._state = "open"

    @property
    def state(self) -> str:
        return self._state


# ============================================================================
# Fallback Buffer
# ============================================================================

class FallbackBuffer:
    """Local JSONL buffer for events when Audit Service is unreachable.

    Disk is the source of truth (append-only JSONL); the in-memory deque is a
    working set loaded at startup. Popped events are only removed from disk
    AFTER the caller confirms successful send (ack), so a crash mid-replay
    re-sends at-least-once (audit events are idempotent via event_id).
    """

    MAX_REPLAY_FILE_BYTES = FALLBACK_MAX_BYTES  # 50MB cap, drop-oldest

    def __init__(self):
        try:
            FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self._queue: deque[dict] = deque()
        self._max_queue = 10_000
        self._replaying = False
        self._load_from_disk()

    def _load_from_disk(self):
        """Load previously buffered events from disk into memory at boot.

        Survives process restarts: events buffered before a crash/redeploy are
        replayed once the audit service is reachable again.
        """
        try:
            if FALLBACK_FILE.exists():
                with open(FALLBACK_FILE, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                        except Exception:
                            continue  # corrupt line — skip
                        if len(self._queue) < self._max_queue:
                            self._queue.append(ev)
                size_kb = FALLBACK_FILE.stat().st_size // 1024
                logger.info(
                    "audit_fallback_reloaded events=%d file_kb=%d",
                    len(self._queue), size_kb,
                )
                # Rewrite the file as just the loaded events (dedupes partial
                # writes from prior runs and keeps file == queue)
                self._rewrite_disk()
        except Exception as e:
            logger.warning("audit_fallback_load_failed error=%s", str(e))

    def push(self, event: AuditEvent) -> bool:
        """Append event to fallback. Returns False if buffer full."""
        if len(self._queue) >= self._max_queue:
            logger.error("audit_fallback_buffer_full")
            return False
        ev_dict = event.model_dump(mode="json")
        self._queue.append(ev_dict)
        self._append_to_disk(ev_dict)
        return True

    def pop_batch(self, count: int) -> List[dict]:
        """Pop up to `count` events from the front of the queue (memory only).

        Caller MUST call ack_batch(events) after successful send, which
        removes them from disk. If not acked, they stay on disk and will be
        re-loaded on next boot.
        """
        batch = []
        while self._queue and len(batch) < count:
            batch.append(self._queue.popleft())
        return batch

    def ack_batch(self, batch: List[dict]):
        """Remove acked events from disk after successful send."""
        if not batch:
            return
        try:
            acked_ids = {id(e) for e in batch}
            remaining = [e for e in self._queue]
            # Rewrite disk with everything still in memory (queue holds
            # un-acked events; acked ones were already popped)
            self._rewrite_disk()
        except Exception as e:
            logger.warning("fallback_ack_failed error=%s", str(e))

    def _append_to_disk(self, ev: dict):
        """Append ONE event to the JSONL file (O(1), no rewrite)."""
        try:
            with open(FALLBACK_FILE, "a") as f:
                f.write(json.dumps(ev, default=str) + "\n")
            # Cap file size: drop-oldest by rewriting without the head
            if FALLBACK_FILE.exists() and FALLBACK_FILE.stat().st_size > self.MAX_REPLAY_FILE_BYTES:
                self._trim_disk()
        except Exception as e:
            logger.warning("fallback_disk_flush_failed error=%s", str(e))

    def _rewrite_disk(self):
        """Rewrite the file to exactly mirror the in-memory queue."""
        try:
            tmp = FALLBACK_FILE.with_suffix(".jsonl.tmp")
            with open(tmp, "w") as f:
                for ev in self._queue:
                    f.write(json.dumps(ev, default=str) + "\n")
            tmp.replace(FALLBACK_FILE)
        except Exception as e:
            logger.warning("fallback_disk_rewrite_failed error=%s", str(e))

    def _trim_disk(self):
        """Drop oldest half of the file when over the size cap."""
        try:
            lines = FALLBACK_FILE.read_text().splitlines(keepends=True)
            keep = lines[len(lines) // 2:]
            tmp = FALLBACK_FILE.with_suffix(".jsonl.tmp")
            tmp.write_text("".join(keep))
            tmp.replace(FALLBACK_FILE)
            # Mirror trim in memory (front of deque == oldest)
            for _ in range(len(self._queue) // 2):
                if self._queue:
                    self._queue.popleft()
            logger.warning("audit_fallback_trimmed remaining=%d", len(self._queue))
        except Exception as e:
            logger.warning("fallback_disk_trim_failed error=%s", str(e))

    @property
    def size(self) -> int:
        return len(self._queue)


# ============================================================================
# Core Client
# ============================================================================

class AuditClient:
    """
    Async audit client with batched ingestion and fail-closed semantics.

    Lifecycle:
        client = AuditClient()
        await client.start()   # opens HTTP pool + starts flush loop
        ... log events ...
        await client.stop()    # drains buffer, closes connections
    """

    def __init__(self):
        self._http: Optional[httpx.AsyncClient] = None
        self._circuit = CircuitBreaker()
        self._buffer = FallbackBuffer()
        self._batch: List[AuditEvent] = []
        self._batch_lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False
        self._service_name = SERVICE_NAME

    # ---- Lifecycle ----

    async def start(self):
        if self._running:
            return
        self._running = True
        self._http = httpx.AsyncClient(
            base_url=GATEWAY_URL,
            timeout=HTTP_TIMEOUT_S,
        )
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("audit_client_started service=%s", self._service_name)

    async def stop(self):
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # Final flush
        await self.flush()
        if self._http:
            await self._http.aclose()
            self._http = None
        logger.info("audit_client_stopped")

    # ---- Public API ----

    async def log(
        self,
        event_type: str,
        resource_id: str,
        *,
        actor_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        action: Optional[str] = None,
        outcome: Outcome = Outcome.SUCCESS,
        category: Category = Category.GENERAL,
        severity: Severity = Severity.INFO,
        ip_address: Optional[str] = None,
        request_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        pii_accessed: bool = False,
        fail_closed: Optional[bool] = None,
    ) -> bool:
        """
        Log an audit event (best-effort batching).

        Args:
            fail_closed: Override default fail-closed. If True and the
                         batch send fails, raises AuditUnavailableError.

        Returns True if the event was accepted into the batch or sent
        successfully. Returns False if buffered locally.
        Raises AuditUnavailableError if fail_closed=True and send fails.
        """
        if not self._running:
            return True

        event = make_event(
            service=self._service_name,
            event_type=event_type,
            category=category,
            severity=severity,
            outcome=outcome,
            action=action,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id,
            ip_address=ip_address,
            payload=payload,
            pii_accessed=pii_accessed,
        )

        should_fail_closed = fail_closed if fail_closed is not None else FAIL_CLOSED_DEFAULT

        async with self._batch_lock:
            self._batch.append(event)
            if len(self._batch) >= BATCH_SIZE:
                return await self._send_batch(should_fail_closed)

        return True

    async def log_event(self, event: AuditEvent, *, fail_closed: Optional[bool] = None) -> bool:
        """Log a pre-built AuditEvent directly."""
        if not self._running:
            return True

        should_fail_closed = fail_closed if fail_closed is not None else FAIL_CLOSED_DEFAULT

        async with self._batch_lock:
            self._batch.append(event)
            if len(self._batch) >= BATCH_SIZE:
                return await self._send_batch(should_fail_closed)

        return True

    async def flush(self) -> bool:
        """Force-flush the current batch."""
        async with self._batch_lock:
            if not self._batch:
                return True
            return await self._send_batch(fail_closed=False)

    # ---- Internal ----

    async def _flush_loop(self):
        """Periodic flush of buffered events + replay of fallback backlog."""
        while self._running:
            try:
                await asyncio.sleep(FLUSH_INTERVAL_S)
                await self.flush()
                await self._replay_backlog()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("audit_flush_loop_error error=%s", str(e))

    async def _send_batch(self, fail_closed: bool) -> bool:
        """Send the current batch via HTTP to Gateway → Audit Service."""
        if not self._batch:
            return True

        events = self._batch[:]
        self._batch.clear()

        # Circuit breaker check
        if self._circuit.is_open:
            logger.warning("audit_circuit_open_buffering count=%d", len(events))
            for ev in events:
                self._buffer.push(ev)
            if fail_closed:
                raise AuditUnavailableError("Audit service circuit breaker open")
            return False

        # Build request
        batch = AuditEventBatch(
            service=self._service_name,
            events=events,
        )
        body = batch.model_dump_json()
        timestamp = datetime.now(timezone.utc).isoformat()
        signature = self._sign(timestamp, body)

        headers = {
            "Content-Type": "application/json",
            "X-Service-Name": self._service_name,
            "X-Service-Timestamp": timestamp,
            "X-Service-Signature": signature,
        }

        try:
            assert self._http is not None
            response = await self._http.post(
                AUDIT_HTTP_PATH,
                content=body,
                headers=headers,
            )

            if response.status_code < 400:
                self._circuit.record_success()
                return True

            logger.warning("audit_batch_rejected status=%s", response.status_code)
            self._circuit.record_failure()

        except httpx.RequestError as e:
            logger.warning("audit_batch_send_failed error=%s", str(e))
            self._circuit.record_failure()

        # Fallback: buffer locally
        for ev in events:
            self._buffer.push(ev)

        if fail_closed:
            raise AuditUnavailableError(
                f"Audit batch send failed ({len(events)} events buffered)"
            )

        return False

    # ---- Backlog replay (gap fix: buffered events were never drained) ----

    async def _replay_backlog(self):
        """Drain the fallback buffer after the circuit recovers.

        Runs on the flush cadence; only sends when the circuit is closed and
        the live batch path is healthy. Reconstructs AuditEvent objects from
        buffered dicts so they go through the normal signed-send path.
        Batches at BATCH_SIZE per cycle to bound memory; acks each batch
        (removed from disk) only after a confirmed send.
        """
        if self._buffer._replaying:
            return
        if self._circuit.state != "closed":
            return  # wait for circuit recovery; live batches probe first
        if self._buffer.size == 0:
            return

        self._buffer._replaying = True
        try:
            for _ in range(4):  # up to 4 batches per cycle (200 events)
                if self._circuit.state != "closed":
                    break
                pending = self._buffer.pop_batch(BATCH_SIZE)
                if not pending:
                    break
                try:
                    batch_obj = AuditEventBatch(
                        service=self._service_name,
                        events=[AuditEvent(**ev) for ev in pending],
                    )
                    body = batch_obj.model_dump_json()
                    timestamp = datetime.now(timezone.utc).isoformat()
                    headers = {
                        "Content-Type": "application/json",
                        "X-Service-Name": self._service_name,
                        "X-Service-Timestamp": timestamp,
                        "X-Service-Signature": self._sign(timestamp, body),
                    }
                    assert self._http is not None
                    response = await self._http.post(
                        AUDIT_HTTP_PATH, content=body, headers=headers
                    )
                    if response.status_code < 400:
                        self._circuit.record_success()
                        self._buffer.ack_batch(pending)
                        logger.info(
                            "audit_backlog_replayed count=%d remaining=%d",
                            len(pending), self._buffer.size,
                        )
                    else:
                        self._circuit.record_failure()
                        # Re-queue at the front; stop replay this cycle
                        self._requeue_front(pending)
                        break
                except httpx.RequestError as e:
                    self._circuit.record_failure()
                    logger.warning("audit_backlog_replay_failed error=%s", str(e))
                    self._requeue_front(pending)
                    break
                except Exception:
                    # Malformed buffered event — drop it (don't poison the well)
                    logger.warning("audit_backlog_bad_event_skipped")
                    self._buffer.ack_batch(pending)
        finally:
            self._buffer._replaying = False

    def _requeue_front(self, pending: List[dict]):
        """Put unsent replay events back at the front of the buffer."""
        for ev in reversed(pending):
            self._buffer._queue.appendleft(ev)

    def _sign(self, timestamp: str, body: str) -> str:
        if not SERVICE_SECRET:
            return ""
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        message = f"{self._service_name}:{timestamp}:{body_hash}"
        return hmac.new(
            SERVICE_SECRET.encode(), message.encode(), hashlib.sha256
        ).hexdigest()


# ============================================================================
# Exceptions
# ============================================================================

class AuditUnavailableError(Exception):
    """Raised when audit logging fails and fail-closed mode is active."""
    pass


# ============================================================================
# Singleton
# ============================================================================

_client: Optional[AuditClient] = None


def get_audit_client() -> AuditClient:
    global _client
    if _client is None:
        _client = AuditClient()
    return _client
