from starlette.responses import JSONResponse
from starlette.requests import Request
from starlette.types import Scope, Receive, Send
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


class _FakeSSLObject:
    def __init__(self, peer_cert):
        self._peer_cert = peer_cert

    def getpeercert(self, binary_form=False):
        return self._peer_cert if binary_form else {}


class _FakeConnection:
    def __init__(self, peer_cert):
        self._ssl_object = _FakeSSLObject(peer_cert) if peer_cert != "NO_SSL" else None


def _run_dispatch(peer_cert, path="/v1/audit/events/bulk", client_ip="172.30.5.23"):
    import asyncio

    from smsly_core.direct_access_protection import (
        DirectAccessProtectionMiddleware,
        _has_tls_peer_cert,
    )

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": path,
        "headers": [(b"content-type", b"application/json")],
        "client": (client_ip, 33164),
        "connection": _FakeConnection(peer_cert),
        "extensions": {"tls": {"client_cert_der": peer_cert}}
        if peer_cert not in (None, "NO_SSL") else {},
    }

    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    messages = []

    async def send(message):
        messages.append(message)

    async def downstream(request):
        return JSONResponse({"status": "ok"})

    mw = DirectAccessProtectionMiddleware.__new__(DirectAccessProtectionMiddleware)
    mw.service_name = "test-service"
    mw.gateway_url = "https://gateway.local"
    mw.max_warnings = 2
    mw.blacklist_hours = 24
    mw.excluded_paths = {"/health", "/ready", "/live", "/metrics"}
    mw._redis = None
    mw._memory_attempts = {}
    mw._memory_blacklist = set()

    import asyncio as _asyncio

    result = _asyncio.run(mw.dispatch(
        Request(scope, receive), downstream,
    ))
    assert _has_tls_peer_cert(Request(scope, receive)) == (peer_cert not in (None, "NO_SSL"))
    return getattr(result, "status_code", None)


def test_mtls_peer_cert_bypasses_enforcement():
    # 2026-09-26: SVID-authenticated callers on :8443 were flagged as
    # direct access and blacklisted. A presented client cert IS access
    # control — enforcement must not apply. Public IP proves the cert
    # (not the dev internal-IP bypass) is what allows it.
    assert _run_dispatch(b"fake-der-cert", client_ip="203.0.113.9") == 200


def test_no_peer_cert_still_enforced():
    # Public IP, no client cert: enforcement unchanged.
    # (Mesh IPs bypass in dev/test envs via is_internal_ip — production
    # requires GATEWAY_IPS or a gateway signature.)
    assert _run_dispatch(None, client_ip="203.0.113.9") == 403
    assert _run_dispatch("NO_SSL", client_ip="203.0.113.9") == 403
