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
    Parse signed request headers.
    
    Args:
        headers: Request headers
        body_hash: Computed body hash
        
    Returns:
        SignedRequest if all required headers present, None otherwise
    """
    try:
        return SignedRequest(
            method=headers.get("X-SMSLY-Method", ""),
            path=headers.get("X-SMSLY-Path", ""),
            timestamp=int(headers.get("X-SMSLY-Timestamp", "0")),
            nonce=headers.get("X-SMSLY-Nonce", ""),
            body_hash=body_hash,
            signature=headers.get("X-SMSLY-Signature", ""),
            key_id=headers.get("X-SMSLY-Key-ID", ""),
        )
    except (ValueError, KeyError) as e:
        logger.warning("Failed to parse signed headers", error=str(e))
        return None
