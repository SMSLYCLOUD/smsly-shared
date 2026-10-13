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


def test_extract_peer_cert_der_prefers_extensions():
    from smsly_core.spiffe_auth import extract_peer_cert_der

    class FakeReq:
        scope = {"extensions": {"tls": {"client_cert_der": b"DER-BYTES"}}}

    assert extract_peer_cert_der(FakeReq()) == b"DER-BYTES"
    assert extract_peer_cert_der({}) is None
    assert extract_peer_cert_der({"extensions": {}}) is None


# ---------------------------------------------------------------- whitelist

def _with_whitelist(monkeypatch, cidrs=None, loopback=None):
    import ipaddress
    import smsly_core.direct_access_protection as dap
    if cidrs is not None:
        monkeypatch.setattr(dap, "WHITELIST_NETS",
                            [ipaddress.ip_network(c) for c in cidrs])
    if loopback is not None:
        monkeypatch.setattr(dap, "WHITELIST_LOOPBACK", loopback)


def test_whitelist_host_route(monkeypatch):
    # Ranges only: a single IP is a /32 host route.
    import smsly_core.direct_access_protection as dap
    _with_whitelist(monkeypatch, cidrs=["203.0.113.10/32"])
    assert dap.is_whitelisted_ip("203.0.113.10")
    assert not dap.is_whitelisted_ip("203.0.113.11")


def test_whitelist_cidr_containment(monkeypatch):
    import smsly_core.direct_access_protection as dap
    _with_whitelist(monkeypatch, cidrs=["172.30.0.0/16"])
    assert dap.is_whitelisted_ip("172.30.5.2")
    assert dap.is_whitelisted_ip("172.30.255.255")
    assert not dap.is_whitelisted_ip("172.31.5.2")
    assert not dap.is_whitelisted_ip("203.0.113.9")


def test_whitelist_loopback_default_on(monkeypatch):
    import smsly_core.direct_access_protection as dap
    _with_whitelist(monkeypatch, cidrs=[], loopback=True)
    assert dap.is_whitelisted_ip("127.0.0.1")
    assert dap.is_whitelisted_ip("::1")
    _with_whitelist(monkeypatch, loopback=False)
    assert not dap.is_whitelisted_ip("127.0.0.1")


def test_whitelist_non_ip_identifier_never_matches(monkeypatch):
    # Ranges only: non-IP client identifiers (e.g. Starlette's
    # "testclient") can no longer bypass accounting.
    import smsly_core.direct_access_protection as dap
    _with_whitelist(monkeypatch, cidrs=["172.30.0.0/16"])
    assert not dap.is_whitelisted_ip("testclient")
    assert not dap.is_whitelisted_ip("otherclient")


def test_whitelist_bare_ip_parsed_as_host_route(monkeypatch):
    # Bare IPs in the CIDR var normalize to /32 (IPv6 /128).
    import os
    import smsly_core.direct_access_protection as dap
    monkeypatch.setenv("DIRECT_ACCESS_WHITELIST_CIDRS", "203.0.113.10,2001:db8::1")
    monkeypatch.setenv("DIRECT_ACCESS_WHITELIST_IPS", "")
    nets = dap._parse_whitelist_cidrs()
    assert len(nets) == 2
    monkeypatch.setattr(dap, "WHITELIST_NETS", nets)
    assert dap.is_whitelisted_ip("203.0.113.10")
    assert not dap.is_whitelisted_ip("203.0.113.11")
    assert dap.is_whitelisted_ip("2001:db8::1")
    assert not dap.is_whitelisted_ip("2001:db8::2")


def test_whitelisted_ip_bypasses_enforcement(monkeypatch):
    # 2026-10-12: identity banned 172.30.5.2 + 127.0.0.1 over unattested
    # probe traffic. A whitelisted mesh IP passes even with zero gateway
    # attestation and max_warnings=0 (immediate-block posture).
    import smsly_core.direct_access_protection as dap
    _with_whitelist(monkeypatch, cidrs=["172.30.0.0/16"])
    scope = {
        "type": "http", "http_version": "1.1", "method": "GET",
        "scheme": "http", "path": "/favicon.ico",
        "headers": [], "client": ("172.30.5.2", 40000),
        "connection": _FakeConnection("NO_SSL"), "extensions": {},
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def downstream(request):
        return JSONResponse({"status": "ok"})

    mw = DirectAccessProtectionMiddleware.__new__(DirectAccessProtectionMiddleware)
    mw.service_name = "test-service"
    mw.gateway_url = "https://gateway.local"
    mw.max_warnings = 0
    mw.blacklist_hours = 24
    mw.excluded_paths = {"/health", "/ready", "/live", "/metrics"}
    mw._redis = None
    mw._memory_attempts = {}
    mw._memory_blacklist = set()

    import asyncio as _asyncio
    result = _asyncio.run(mw.dispatch(Request(scope, receive), downstream))
    assert getattr(result, "status_code", None) == 200
    # No warn budget burned, no blacklist entry written.
    assert mw._memory_attempts == {}
    assert mw._memory_blacklist == set()


def test_whitelist_ignores_existing_blacklist(monkeypatch):
    # Whitelisting un-bans live: a pre-blacklisted IP passes once listed.
    import smsly_core.direct_access_protection as dap
    _with_whitelist(monkeypatch, cidrs=["203.0.113.77/32"])
    scope = {
        "type": "http", "http_version": "1.1", "method": "GET",
        "scheme": "http", "path": "/v1/messages",
        "headers": [], "client": ("203.0.113.77", 40001),
        "connection": _FakeConnection("NO_SSL"), "extensions": {},
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def downstream(request):
        return JSONResponse({"status": "ok"})

    mw = DirectAccessProtectionMiddleware.__new__(DirectAccessProtectionMiddleware)
    mw.service_name = "test-service"
    mw.gateway_url = "https://gateway.local"
    mw.max_warnings = 2
    mw.blacklist_hours = 24
    mw.excluded_paths = {"/health"}
    mw._redis = None
    mw._memory_attempts = {}
    mw._memory_blacklist = {"203.0.113.77"}

    import asyncio as _asyncio
    result = _asyncio.run(mw.dispatch(Request(scope, receive), downstream))
    assert getattr(result, "status_code", None) == 200
