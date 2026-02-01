import pytest
from starlette.responses import JSONResponse
from starlette.requests import Request
from starlette.types import Scope, Receive, Send
from unittest.mock import MagicMock, patch
import os
import hashlib
import hmac
from datetime import datetime, timezone

from smsly_core.direct_access_protection import DirectAccessProtectionMiddleware

# Mock App
async def mock_app(scope: Scope, receive: Receive, send: Send):
    # Try to read the body to ensure middleware didn't consume it
    request = Request(scope, receive)
    body = await request.body()
    # Echo back body length to prove we read it
    response = JSONResponse({"status": "ok", "body_size": len(body)})
    await response(scope, receive, send)

# Use TestClient for easier testing
from starlette.testclient import TestClient

def create_client(secret="test-secret"):
    os.environ["GATEWAY_SECRET"] = secret
    os.environ["GATEWAY_IPS"] = "10.0.0.1"

    app = DirectAccessProtectionMiddleware(mock_app, max_warnings=0) # 0 warnings = immediate block after 1st attempt?
    # Logic: if attempt_count > max_warnings: block
    # If max_warnings=0, 1st attempt is attempt_count=1. 1 > 0 -> Block.

    return TestClient(app)

def test_allow_gateway_ip_client():
    client = create_client()
    # Mock client host? TestClient defaults to testclient (127.0.0.1?)
    # We need to simulate IP.
    # Starlette TestClient doesn't easily allow setting client IP per request without subclassing/hacking.
    # But 127.0.0.1 is in INTERNAL_PREFIXES, so it might pass `is_internal_ip` check inside `is_gateway_ip`.
    # `is_gateway_ip` logic: if GATEWAY_IPS set, check that.
    # In my patch `GATEWAY_IPS` is set to "10.0.0.1".
    # So 127.0.0.1 should fail `is_gateway_ip`.

    # TestClient request
    response = client.get("/api/test")
    # Should be blocked (403) because IP is not 10.0.0.1 and no signature
    assert response.status_code == 403
    assert response.json()["code"] == "IP_BLOCKED_AND_BLACKLISTED"

def test_allow_valid_signature():
    secret = "test-secret"
    client = create_client(secret)

    timestamp = datetime.now(timezone.utc).isoformat()
    path = "/api/test"

    # Sign
    msg = f"{timestamp}:{path}"
    signature = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

    headers = {
        "X-Gateway-Timestamp": timestamp,
        "X-Gateway-Signature": signature
    }

    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_block_invalid_signature():
    secret = "test-secret"
    client = create_client(secret)

    timestamp = datetime.now(timezone.utc).isoformat()
    path = "/api/test"

    # Invalid signature
    signature = "invalid"

    headers = {
        "X-Gateway-Timestamp": timestamp,
        "X-Gateway-Signature": signature
    }

    response = client.get(path, headers=headers)
    assert response.status_code == 403

def test_block_expired_signature():
    secret = "test-secret"
    client = create_client(secret)

    # Old timestamp
    timestamp = "2020-01-01T00:00:00+00:00"
    path = "/api/test"

    msg = f"{timestamp}:{path}"
    signature = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

    headers = {
        "X-Gateway-Timestamp": timestamp,
        "X-Gateway-Signature": signature
    }

    response = client.get(path, headers=headers)
    assert response.status_code == 403

def test_allow_signature_with_body():
    secret = "test-secret"
    client = create_client(secret)

    timestamp = datetime.now(timezone.utc).isoformat()
    path = "/api/test"
    body = b"test-body"

    body_hash = hashlib.sha256(body).hexdigest()
    msg = f"{timestamp}:{path}:{body_hash}"
    signature = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

    headers = {
        "X-Gateway-Timestamp": timestamp,
        "X-Gateway-Signature": signature
    }

    response = client.post(path, headers=headers, content=body)
    assert response.status_code == 200
    # Verify app received the body
    assert response.json()["body_size"] == len(body)
