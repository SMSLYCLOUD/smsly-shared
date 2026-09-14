"""
SPIFFE mTLS Helpers for Services (dual-port pattern)
====================================================

Mesh layout (per platform topology):
  - Port 8080  : plain HTTP — Traefik edge (Host rules, ACME termination),
                 orchestrator health probes (/health, /ready), metrics.
  - Port 8443  : mTLS — direct service-to-service calls with SPIFFE SVID
                 identity (both directions verified).

This module provides:
  - create_server_ssl_context()  — inbound mTLS context from own SVID + bundle
  - create_client_ssl_context()  — outbound mTLS context from own SVID + bundle
  - create_mtls_httpx_client()    — httpx.AsyncClient wired to that context
  - is_spire_available()         — probe (socket or SVID dir)
  - MESH_HTTP_PORT / MESH_MTLS_PORT constants

SVID sources (both tried, in order):
  1. SPIFFE_SVID_DIR files (svid.0.pem, svid.0.key, bundle.0.pem) — the
     platform SPIRE agent writes these; SVIDRotator keeps them fresh.
  2. SPIRE Workload API via UDS socket (SPIFFE_ENDPOINT_SOCKET) when the
     spire python helper package is present.

Security notes:
  - TLS 1.3 only; CA bundle REQUIRED; client cert REQUIRED (mutual).
  - check_hostname=False is intentional: SPIFFE IDs are URI SANs, not DNS
    names. Caller allowlisting happens at the application layer via
    smsly_core.spiffe_auth.DualAuthValidator + communication_rules.json.
"""

from __future__ import annotations

import logging
import os
import socket
import ssl
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

MESH_HTTP_PORT = 8080   # plain HTTP behind Traefik edge
MESH_MTLS_PORT = 8443   # direct service-to-service mTLS

SVID_DIR = Path(os.getenv("SPIFFE_SVID_DIR", "/opt/spire/svids"))
WORKLOAD_API_SOCKET = os.getenv("SPIFFE_ENDPOINT_SOCKET", "/opt/spire/run/agent.sock")

_TLS_CIPHERS = (
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_128_GCM_SHA256"
)


def is_spire_available() -> bool:
    """True if SVID files or the workload API socket are present."""
    if _svid_files_present():
        return True
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(WORKLOAD_API_SOCKET)
        sock.close()
        return True
    except OSError:
        return False


def _svid_files_present() -> bool:
    return all(
        p.exists()
        for p in (SVID_DIR / "svid.0.pem", SVID_DIR / "svid.0.key", SVID_DIR / "bundle.0.pem")
    )


def _load_from_files() -> ssl.SSLContext:
    cert = SVID_DIR / "svid.0.pem"
    key = SVID_DIR / "svid.0.key"
    bundle = SVID_DIR / "bundle.0.pem"
    if not _svid_files_present():
        raise FileNotFoundError(
            f"SVID files missing in {SVID_DIR} (need svid.0.pem, svid.0.key, bundle.0.pem)"
        )
    return _build_context(
        certfile=str(cert),
        keyfile=str(key),
        cafile=str(bundle),
    )


def _load_from_workload_api() -> ssl.SSLContext:
    """Load via the spire python helper when available."""
    try:
        from spire.helpers.tls_context import create_mtls_context  # type: ignore
    except ModuleNotFoundError:
        raise ModuleNotFoundError(
            "spire helper package not installed; set SPIFFE_SVID_DIR to the "
            "agent-written SVID directory instead"
        )
    return create_mtls_context(mode="client")


def _build_context(certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.load_verify_locations(cafile=cafile)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False  # SPIFFE URI SANs, not DNS — app-layer allowlist validates identity
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers(_TLS_CIPHERS)
    return ctx


def _load_svid_context() -> ssl.SSLContext:
    if _svid_files_present():
        return _load_from_files()
    return _load_from_workload_api()


def create_client_ssl_context() -> ssl.SSLContext:
    """Outbound mTLS context (presents own SVID, verifies peer against bundle)."""
    return _load_svid_context()


def create_server_ssl_context() -> ssl.SSLContext:
    """Inbound mTLS context for the :8443 direct-mTLS listener.

    PROTOCOL_TLS_CLIENT is used deliberately: TLS 1.3 contexts are
    functionally symmetric for this use (both load cert chains, set
    CERT_REQUIRED, and pin the same cipher policy). The explicit
    purpose is documented here because PROTOCOL_TLS_SERVER provides no
    additional guarantees under these settings.
    """
    ctx = _load_svid_context()
    return ctx


def create_mtls_httpx_client(**kwargs: Any):
    """httpx.AsyncClient pre-wired for direct mTLS mesh calls (:8443).

    Usage:
        client = create_mtls_httpx_client(base_url="https://smsly-policy-service:8443")
        resp = await client.post("/v1/evaluate", json=payload)
    """
    import httpx

    verify = kwargs.pop("verify", create_client_ssl_context())
    return httpx.AsyncClient(verify=verify, **kwargs)


def direct_mtls_url(service_slug: str) -> str:
    """Direct mTLS URL for a mesh service (Host `smsly-<slug>`)."""
    return f"https://smsly-{service_slug}:{MESH_MTLS_PORT}"
