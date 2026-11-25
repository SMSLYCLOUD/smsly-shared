"""
Header Functions
=================
Functions for creating and parsing signed request headers.
"""

import time
from typing import Dict, Optional
import structlog

from .models import SignedRequest
from .signature import compute_signature, hash_body, generate_nonce

logger = structlog.get_logger(__name__)


def create_signed_headers(
    secret: str,
    key_id: str,
    method: str,
    path: str,
    body: bytes = b"",
) -> Dict[str, str]:
    """
    Create headers for a signed request.
    
    Args:
        secret: API key secret or shared secret
        key_id: API key ID for identification
        method: HTTP method
        path: Request path
        body: Request body (optional)
        
    Returns:
        Dictionary of headers to include in request
    """
    timestamp = int(time.time())
    nonce = generate_nonce()
    body_hash_value = hash_body(body)
    signature = compute_signature(
        secret, method, path, timestamp, nonce, body_hash_value
    )
    
    return {
        "X-TRULAY-Key-ID": key_id,
        "X-TRULAY-Timestamp": str(timestamp),
        "X-TRULAY-Nonce": nonce,
        "X-TRULAY-Signature": signature,
        "X-SMSLY-Key-ID": key_id,
        "X-SMSLY-Timestamp": str(timestamp),
        "X-SMSLY-Nonce": nonce,
        "X-SMSLY-Signature": signature,
    }


def parse_signed_headers(
    headers: Dict[str, str],
    body_hash: str
) -> Optional[SignedRequest]:
    """
    Parse signed request headers (supports both X-TRULAY-* and X-SMSLY-* case-insensitively).
    
    Args:
        headers: Request headers
        body_hash: Computed body hash
        
    Returns:
        SignedRequest if all required headers present, None otherwise
    """
    if not headers:
        return None
    try:
        lower = {str(k).lower(): v for k, v in headers.items() if v is not None}
        key_id = lower.get("x-trulay-key-id") or lower.get("x-smsly-key-id") or ""
        signature = lower.get("x-trulay-signature") or lower.get("x-smsly-signature") or ""
        nonce = lower.get("x-trulay-nonce") or lower.get("x-smsly-nonce") or ""
        ts_raw = lower.get("x-trulay-timestamp") or lower.get("x-smsly-timestamp") or ""
        method = lower.get("x-trulay-method") or lower.get("x-smsly-method") or ""
        path = lower.get("x-trulay-path") or lower.get("x-smsly-path") or ""

        if not key_id or not signature or not nonce or not ts_raw:
            return None

        return SignedRequest(
            method=method,
            path=path,
            timestamp=int(ts_raw),
            nonce=nonce,
            body_hash=body_hash,
            signature=signature,
            key_id=key_id,
        )
    except (ValueError, KeyError, TypeError) as e:
        logger.warning("Failed to parse signed headers", error=str(e))
        return None
