"""
Transaction-chain client (sync + async) for SMSLY services.

Implements the queue_transaction_sync interface the backend's payments
module imports (previously a dead import — module never existed).

Everything routes via the Security Gateway mesh:
    {SECURITY_GATEWAY_URL}/chain/v1/transactions
"""

from __future__ import annotations

import hashlib
import logging
import os
import ssl
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

_ORIG_REQUESTS_POST = requests.post

_CHAIN_URL = os.getenv(
    "TRANSACTION_CHAIN_URL",
    os.getenv("SECURITY_GATEWAY_URL", "https://smsly-security-gateway:80") + "/chain",
).rstrip("/")

_MESH_HEADERS = {
    "X-TRULAY-Validated": "true",
    "X-Smsly-Validated": "true",
    "X-Forwarded-Proto": "https",
    "Content-Type": "application/json",
}


def _bounded_chain_id(raw: Optional[str]) -> str:
    """Guarantee chain correlation_id / resource_id fits VARCHAR(64)."""
    trimmed = str(raw or "").strip()
    if not trimmed:
        return "unspecified"
    candidate = trimmed[2:] if trimmed.lower().startswith("0x") else trimmed
    if len(candidate) == 64 and all(c in "0123456789abcdefABCDEF" for c in candidate):
        return candidate.lower()
    if len(trimmed) <= 64:
        return trimmed
    digest = hashlib.sha256(trimmed.encode("utf-8")).hexdigest()
    return f"id_{digest[:61]}"


def _verify_for_url(url: str):
    """Route to smsly_core.mtls.verify_for_url (SVID ctx for :8443, mesh
    ctx for :80 Traefik, passthrough for http). Never raises."""
    try:
        from smsly_core.mtls import verify_for_url as _router
        return _router(url)
    except Exception as e:
        logger.warning("chain_mtls_unavailable_standard_verify error=%s", e)
        return url.startswith("https://")


def _chain_headers() -> Dict[str, str]:
    headers = dict(_MESH_HEADERS)
    gw_secret = (
        os.getenv("GATEWAY_TO_CHAIN_SECRET", "").strip()
        or os.getenv("GATEWAY_SECRET", "").strip()
    )
    internal_secret = os.getenv("INTERNAL_API_SECRET", "").strip()
    if gw_secret:
        headers["X-Gateway-Secret"] = gw_secret
    if internal_secret:
        headers["X-Internal-Secret"] = internal_secret
        headers["Authorization"] = f"Bearer {internal_secret}"
    elif gw_secret:
        headers["Authorization"] = f"Bearer {gw_secret}"
    return headers


def _post_sync(url: str, payload: Dict[str, Any], headers: Dict[str, str], timeout: float):
    """POST JSON synchronously while supporting ssl.SSLContext from verify_for_url."""
    verify = _verify_for_url(url)
    # Preserve compatibility with unit tests that monkeypatch requests.post
    if requests.post is not _ORIG_REQUESTS_POST:
        safe_verify = True if isinstance(verify, ssl.SSLContext) else verify
        return requests.post(url, json=payload, headers=headers, timeout=timeout, verify=safe_verify)

    if isinstance(verify, ssl.SSLContext):
        try:
            import httpx
            with httpx.Client(timeout=timeout, verify=verify) as client:
                return client.post(url, json=payload, headers=headers)
        except ImportError:
            from requests.adapters import HTTPAdapter

            class _SSLContextAdapter(HTTPAdapter):
                def __init__(self, ssl_context: ssl.SSLContext, **kw: Any):
                    self._ssl_context = ssl_context
                    super().__init__(**kw)

                def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kw: Any):
                    pool_kw["ssl_context"] = self._ssl_context
                    return super().init_poolmanager(connections, maxsize, block=block, **pool_kw)

            with requests.Session() as sess:
                sess.mount("https://", _SSLContextAdapter(verify))
                return sess.post(url, json=payload, headers=headers, timeout=timeout, verify=True)

    return requests.post(url, json=payload, headers=headers, timeout=timeout, verify=verify)


_VALID_TX_STATUSES = {"pending", "confirmed", "failed"}
_VALID_TX_OUTCOMES = {"success", "failure", "timeout", "blocked"}


def _build_tx(
    *,
    correlation_id: str,
    service: str,
    tx_type: str,
    actor_id: str,
    actor_type: Optional[str] = None,
    organization_id: Optional[str] = None,
    parent_tx_id: Optional[str] = None,
    outcome: Optional[str] = None,
    status: Optional[str] = None,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    amount=None,
    currency: str = "NGN",
    payload: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    external_ref: Optional[str] = None,
) -> Dict[str, Any]:
    norm_outcome = str(outcome).strip().lower() if outcome is not None else None
    norm_status = str(status).strip().lower() if status is not None else None

    resolved_status: Optional[str] = None
    if norm_status in _VALID_TX_STATUSES:
        resolved_status = norm_status
    elif norm_status in ("queued", "accepted", "processing"):
        resolved_status = "pending"

    resolved_outcome: Optional[str] = None
    if norm_outcome in _VALID_TX_OUTCOMES:
        resolved_outcome = norm_outcome
    elif norm_outcome in _VALID_TX_STATUSES and resolved_status is None:
        resolved_status = norm_outcome
    elif norm_outcome in ("queued", "accepted", "processing") and resolved_status is None:
        resolved_status = "pending"

    tx: Dict[str, Any] = {
        "correlation_id": _bounded_chain_id(correlation_id),
        "service": str(service)[:64],
        "tx_type": str(tx_type)[:64],
        "actor_id": str(actor_id or "system")[:128],
        "payload": payload or {},
    }
    if actor_type:
        tx["actor_type"] = str(actor_type)[:32]
    if organization_id:
        tx["organization_id"] = str(organization_id)[:128]
    if parent_tx_id:
        tx["parent_tx_id"] = _bounded_chain_id(parent_tx_id)
    if resolved_status:
        tx["status"] = resolved_status
    if resolved_outcome:
        tx["outcome"] = resolved_outcome
    if error_code:
        tx["error_code"] = str(error_code)[:64]
    if error_message:
        tx["error_message"] = str(error_message)[:500]
    if resource_type:
        tx["resource_type"] = str(resource_type)[:64]
    if resource_id:
        tx["resource_id"] = _bounded_chain_id(resource_id)
    if amount is not None:
        tx["amount"] = str(amount)
        tx["currency"] = str(currency or "NGN")[:10]
    if metadata:
        tx["metadata"] = metadata
    if external_ref:
        tx["external_ref"] = str(external_ref)[:255]
    return tx


def queue_transaction_sync(
    *,
    correlation_id: str,
    service: str,
    tx_type: str,
    actor_id: str,
    actor_type: Optional[str] = None,
    organization_id: Optional[str] = None,
    parent_tx_id: Optional[str] = None,
    outcome: Optional[str] = None,
    status: Optional[str] = None,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    amount=None,
    currency: str = "NGN",
    payload: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    external_ref: Optional[str] = None,
    timeout: float = 5.0,
) -> Optional[str]:
    """
    Record a chain transaction synchronously (worker threads, Celery tasks,
    Django views). Returns the chain tx_id or None (fail-open — the chain
    is an observability ledger, never a business gate).
    """
    tx = _build_tx(
        correlation_id=correlation_id,
        service=service,
        tx_type=tx_type,
        actor_id=actor_id,
        actor_type=actor_type,
        organization_id=organization_id,
        parent_tx_id=parent_tx_id,
        outcome=outcome,
        status=status,
        error_code=error_code,
        error_message=error_message,
        resource_type=resource_type,
        resource_id=resource_id,
        amount=amount,
        currency=currency,
        payload=payload,
        metadata=metadata,
        external_ref=external_ref,
    )
    try:
        resp = _post_sync(
            f"{_CHAIN_URL}/v1/transactions",
            tx,
            _chain_headers(),
            timeout,
        )
        if resp.status_code in (200, 201):
            return resp.json().get("tx_id")
        logger.warning("chain_tx_rejected status=%s body=%s", resp.status_code, resp.text[:200])
    except Exception as e:
        logger.warning("chain_tx_failed error=%s", e)
    return None


def queue_transactions_bulk_sync(transactions: list[Dict[str, Any]], timeout: float = 10.0) -> int:
    """Batch-record transactions synchronously. Returns success count."""
    if not transactions:
        return 0
    try:
        resp = _post_sync(
            f"{_CHAIN_URL}/v1/transactions/bulk",
            {"transactions": transactions},
            _chain_headers(),
            timeout,
        )
        if resp.status_code in (200, 201):
            return int(resp.json().get("success", 0))
    except Exception as e:
        logger.warning("chain_bulk_failed error=%s", e)
    return 0


async def queue_transaction_async(**kwargs) -> Optional[str]:
    """Async variant of queue_transaction_sync (timeout kwarg accepted)."""
    import httpx

    timeout = float(kwargs.pop("timeout", 5.0))
    tx = _build_tx(**kwargs)
    verify = _verify_for_url(_CHAIN_URL)
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=verify) as client:
            resp = await client.post(
                f"{_CHAIN_URL}/v1/transactions",
                json=tx,
                headers=_chain_headers(),
            )
            if resp.status_code in (200, 201):
                return resp.json().get("tx_id")
        logger.warning("chain_tx_rejected status=%s", resp.status_code)
    except Exception as e:
        logger.warning("chain_tx_failed error=%s", e)
    return None


# Alias used by SMSLY services (SMS message_service & VERIFICATION import this name)
queue_transaction = queue_transaction_async


__all__ = [
    "queue_transaction_sync",
    "queue_transactions_bulk_sync",
    "queue_transaction_async",
    "queue_transaction",
]
