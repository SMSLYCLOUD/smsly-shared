"""
Transaction-chain client (sync + async) for SMSLY services.

Implements the queue_transaction_sync interface the backend's payments
module imports (previously a dead import — module never existed).

Everything routes via the Security Gateway mesh:
    {SECURITY_GATEWAY_URL}/chain/v1/transactions
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_CHAIN_URL = os.getenv(
    "TRANSACTION_CHAIN_URL",
    os.getenv("SECURITY_GATEWAY_URL", "https://smsly-security-gateway:8080") + "/chain",
)


def _build_tx(
    *,
    correlation_id: str,
    service: str,
    tx_type: str,
    actor_id: str,
    parent_tx_id: Optional[str] = None,
    outcome: Optional[str] = None,
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
    tx: Dict[str, Any] = {
        "correlation_id": correlation_id,
        "service": service,
        "tx_type": tx_type,
        "actor_id": actor_id,
        "payload": payload or {},
    }
    if parent_tx_id:
        tx["parent_tx_id"] = parent_tx_id
    if outcome:
        tx["outcome"] = outcome
    if error_code:
        tx["error_code"] = error_code
    if error_message:
        tx["error_message"] = str(error_message)[:500]
    if resource_type:
        tx["resource_type"] = resource_type
    if resource_id:
        tx["resource_id"] = str(resource_id)
    if amount is not None:
        tx["amount"] = str(amount)
        tx["currency"] = currency
    if metadata:
        tx["metadata"] = metadata
    if external_ref:
        tx["external_ref"] = str(external_ref)
    return tx


def queue_transaction_sync(
    *,
    correlation_id: str,
    service: str,
    tx_type: str,
    actor_id: str,
    parent_tx_id: Optional[str] = None,
    outcome: Optional[str] = None,
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
    import requests

    tx = _build_tx(
        correlation_id=correlation_id,
        service=service,
        tx_type=tx_type,
        actor_id=actor_id,
        parent_tx_id=parent_tx_id,
        outcome=outcome,
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
        resp = requests.post(f"{_CHAIN_URL}/v1/transactions", json=tx, timeout=timeout)
        if resp.status_code in (200, 201):
            return resp.json().get("tx_id")
        logger.warning("chain_tx_rejected status=%s body=%s", resp.status_code, resp.text[:200])
    except Exception as e:
        logger.warning("chain_tx_failed error=%s", e)
    return None


def queue_transactions_bulk_sync(transactions: list[Dict[str, Any]], timeout: float = 10.0) -> int:
    """Batch-record transactions synchronously. Returns success count."""
    import requests

    if not transactions:
        return 0
    try:
        resp = requests.post(
            f"{_CHAIN_URL}/v1/transactions/bulk",
            json={"transactions": transactions},
            timeout=timeout,
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
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(f"{_CHAIN_URL}/v1/transactions", json=tx)
            if resp.status_code in (200, 201):
                return resp.json().get("tx_id")
        logger.warning("chain_tx_rejected status=%s", resp.status_code)
    except Exception as e:
        logger.warning("chain_tx_failed error=%s", e)
    return None


__all__ = [
    "queue_transaction_sync",
    "queue_transactions_bulk_sync",
    "queue_transaction_async",
]
