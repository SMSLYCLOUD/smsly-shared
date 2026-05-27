"""
Webhook Signature Validators
=============================
Validates inbound webhook payloads from third-party providers (Twilio,
Meta/WhatsApp, Stripe, Coinbase) using their standard HMAC signature schemes.

Usage:
    from smsly_core.webhook_validators import (
        validate_twilio_signature,
        validate_whatsapp_signature,
        validate_stripe_signature,
    )

    valid = await validate_twilio_signature(request, auth_token)
    valid = await validate_whatsapp_signature(request, app_secret)
    valid, payload = await validate_stripe_signature(request, webhook_secret)
"""

import hashlib
import hmac
import os
import json
from typing import Optional, Tuple

# ─────────────────────────────── Twilio ────────────────────────────────

async def validate_twilio_signature(request, auth_token: str) -> bool:
    """
    Validate Twilio request signature (X-Twilio-Signature header).

    Twilio signs the full request URL + sorted POST params with HMAC-SHA1.

    Args:
        request: FastAPI/Starlette Request
        auth_token: Twilio Auth Token for this account

    Returns:
        True if signature is valid
    """
    if not auth_token:
        return False

    signature = request.headers.get("X-Twilio-Signature")
    if not signature:
        return False

    # Reconstruct the full URL Twilio signed
    url = str(request.url)

    # Collect POST params
    try:
        form = await request.form()
        params = {k: v for k, v in form.items()}
        # Restore the body for downstream
        if hasattr(request, '_receive'):
            body = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
            async def receive_body():
                return {"type": "http.request", "body": body.encode(), "more_body": False}
            request._receive = receive_body
    except Exception:
        params = {}

    # Compute expected signature: HMAC-SHA1(full_url, auth_token)
    import urllib.parse
    sorted_params = sorted(params.items())
    data = url
    for key, value in sorted_params:
        data += key + str(value)

    expected = hmac.new(
        auth_token.encode(),
        data.encode(),
        hashlib.sha1
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


# ────────────────────────────── WhatsApp ───────────────────────────────

async def validate_whatsapp_signature(request, app_secret: str) -> bool:
    """
    Validate Meta WhatsApp webhook signature (X-Hub-Signature-256 header).

    Meta signs the raw request body with HMAC-SHA256 using the app secret.

    Args:
        request: FastAPI/Starlette Request
        app_secret: WhatsApp application secret

    Returns:
        True if signature is valid
    """
    if not app_secret:
        return False

    signature_header = request.headers.get("X-Hub-Signature-256")
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected_prefix = signature_header[7:]  # Remove "sha256="

    # Read body
    try:
        body = await request.body()
        # Restore body
        async def receive_body():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = receive_body
    except Exception:
        return False

    expected = hmac.new(
        app_secret.encode() if isinstance(app_secret, str) else app_secret,
        body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, expected_prefix)


# ─────────────────────────────── Stripe ────────────────────────────────

async def validate_stripe_signature(request, webhook_secret: str) -> Tuple[bool, Optional[dict]]:
    """
    Validate Stripe webhook signature (Stripe-Signature header).

    Uses Stripe's standard approach with signed timestamp and versioned schemes.

    Args:
        request: FastAPI/Starlette Request
        webhook_secret: Stripe webhook signing secret (whsec_...)

    Returns:
        (valid, payload_dict) tuple — payload is parsed JSON if valid
    """
    if not webhook_secret:
        return False, None

    try:
        import stripe
    except ImportError:
        # Fall back to manual verification if stripe lib is not installed
        return await _validate_stripe_manual(request, webhook_secret)

    payload = None
    try:
        body = await request.body()
        async def receive_body():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = receive_body

        sig_header = request.headers.get("Stripe-Signature")
        if not sig_header or not body:
            return False, None

        event = stripe.Webhook.construct_event(
            payload=body,
            sig_header=sig_header,
            secret=webhook_secret,
        )
        return True, event.get("data", {}).get("object", {})
    except stripe.error.SignatureVerificationError:
        return False, None
    except Exception:
        # Parse body as JSON even if verification failed
        if payload:
            try:
                return False, json.loads(payload)
            except Exception:
                pass
        return False, None


async def _validate_stripe_manual(request, webhook_secret: str) -> Tuple[bool, Optional[dict]]:
    """
    Manual Stripe signature validation (no stripe library dependency).

    Stripe signs: timestamp.payload with HMAC-SHA256.
    Header format: t=TIMESTAMP,v1=SIGNATURE[,...]
    """
    sig_header = request.headers.get("Stripe-Signature", "")
    if not sig_header or not webhook_secret:
        return False, None

    try:
        body = await request.body()
        async def receive_body():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = receive_body
    except Exception:
        return False, None

    if not body:
        return False, None

    # Parse signature header
    parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)
    timestamp = parts.get("t", "")
    expected_sig = parts.get("v1", "")
    if not timestamp or not expected_sig:
        return False, None

    signed_payload = f"{timestamp}.{body.decode('utf-8')}"
    computed = hmac.new(
        webhook_secret.encode('utf-8'),
        signed_payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    valid = hmac.compare_digest(computed, expected_sig)
    if valid:
        try:
            return True, json.loads(body)
        except Exception:
            return True, {"raw": body}
    return False, None


# ─────────────────────────────── Coinbase ──────────────────────────────

async def validate_coinbase_signature(request, webhook_secret: str) -> bool:
    """
    Validate Coinbase Commerce webhook signature (X-CC-Webhook-Signature header).

    HMAC-SHA256 of the raw request body.
    """
    if not webhook_secret:
        return False

    sig = request.headers.get("X-CC-Webhook-Signature")
    if not sig:
        return False

    try:
        body = await request.body()
        async def receive_body():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = receive_body
    except Exception:
        return False

    expected = hmac.new(
        webhook_secret.encode(),
        body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, sig)


__all__ = [
    "validate_twilio_signature",
    "validate_whatsapp_signature",
    "validate_stripe_signature",
    "validate_coinbase_signature",
]
