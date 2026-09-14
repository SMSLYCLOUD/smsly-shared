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
  - create_mesh_client_context() — outbound context for :80 Traefik mesh
    (system CA chain verification, hostname check off — internal mesh
    names never match public certs; edge identity is the Traefik Host rule)
  - verify_for_url()             — route any mesh URL to the right verify
    setting (SVID ctx for :8443, mesh ctx for other https, False for http)
  - create_mtls_httpx_client()    — httpx.AsyncClient wired to SVID context
  - SVID lifecycle: build_tag()/is_stale()/svid_expiring_soon()/
    is_cert_expired_error()/start_svid_watcher() — expiry-aware refresh
    for long-lived clients and :8443 listeners (SVID TTL is 1h)
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
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

MESH_HTTP_PORT = 8080   # plain HTTP behind Traefik edge
MESH_MTLS_PORT = 8443   # direct service-to-service mTLS

# Rebuild long-lived TLS clients/listeners when the loaded SVID has less
# than this much lifetime left (SVID TTL is 1h — 15min gives rotation ample
# headroom even if the agent is late).
REFRESH_THRESHOLD_SECONDS = 15 * 60
# Cache negative/positive expiry probes briefly — cert parsing on every
# hot-path call would be wasteful.
_CHECK_CACHE_TTL_SECONDS = 60.0
_check_cache: dict = {"at": 0.0, "expiring": False, "tag": ""}

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


# ---------------------------------------------------------------------------
# Mesh verify routing
# ---------------------------------------------------------------------------

def create_mesh_client_context() -> ssl.SSLContext:
    """Outbound context for :80 Traefik-mesh calls.

    The edge presents a public-chain (ACME) cert for an internal mesh name,
    so the chain verifies against system roots but the hostname can never
    match — check_hostname stays off. Edge identity is the Traefik Host
    rule; caller identity is enforced app-side (DualAuthValidator /
    gateway headers), never by this handshake.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    return ctx


def verify_for_url(url: str, prefer_mtls: bool = True):
    """Route any mesh URL to the correct httpx `verify` setting.

    - http://...                    -> False (plain mesh, no TLS)
    - https://...:8443...           -> SVID client context (direct mTLS);
                                       falls back to mesh context with a
                                       warning when SVIDs are unavailable
    - other https://...             -> mesh context (system CA, no hostname
                                       check) — Traefik edge termination

    Never raises: worst case returns True (standard verification), matching
    httpx's default.
    """
    try:
        if not url.startswith("https://"):
            return False
        if f":{MESH_MTLS_PORT}" in url and prefer_mtls:
            try:
                return create_client_ssl_context()
            except Exception as e:
                logger.warning(
                    "mtls_unavailable_mesh_verify error=%s", e,
                )
        return create_mesh_client_context()
    except Exception as e:
        logger.warning("mesh_verify_fallback_standard error=%s", e)
        return True


# ---------------------------------------------------------------------------
# SVID lifecycle (expiry-aware refresh)
# ---------------------------------------------------------------------------

def _svid_cert_path() -> Path:
    return SVID_DIR / "svid.0.pem"


def get_svid_not_after() -> Optional[datetime]:
    """Expiry of the currently-mounted SVID, or None if unreadable."""
    try:
        from cryptography import x509 as _x509

        data = _svid_cert_path().read_bytes()
        try:
            cert = _x509.load_pem_x509_certificate(data)
        except ValueError:
            cert = _x509.load_der_x509_certificate(data)
        na = cert.not_valid_after_utc
        if na.tzinfo is None:
            na = na.replace(tzinfo=timezone.utc)
        return na
    except Exception:
        return None


def build_tag() -> str:
    """Opaque tag of the currently-mounted SVID (rotation + expiry).

    Long-lived clients record this at construction; a tag change means the
    agent rotated files (rebuild to pick up the fresh cert).
    """
    try:
        p = _svid_cert_path()
        st = p.stat()
        na = get_svid_not_after()
        return f"{st.st_mtime_ns}:{st.st_size}:{(na.isoformat() if na else '-')}"
    except OSError:
        return ""


def _uncached_expiring_soon(threshold_seconds: int) -> bool:
    na = get_svid_not_after()
    if na is None:
        return False  # unreadable (dev/no SPIRE) — nothing to refresh
    remaining = (na - datetime.now(timezone.utc)).total_seconds()
    return remaining < threshold_seconds


def svid_expiring_soon(threshold_seconds: int = REFRESH_THRESHOLD_SECONDS) -> bool:
    """True if the mounted SVID expires within `threshold_seconds`.

    Result cached briefly to keep hot paths cheap.
    """
    now = time.monotonic()
    if now - _check_cache["at"] < _CHECK_CACHE_TTL_SECONDS:
        return _check_cache["expiring"]
    expiring = _uncached_expiring_soon(threshold_seconds)
    _check_cache.update(at=now, expiring=expiring)
    return expiring


def is_stale(tag: Optional[str], threshold_seconds: int = REFRESH_THRESHOLD_SECONDS) -> bool:
    """True if a client/listener built under `tag` should rebuild.

    Stale when: never tagged (None/""), the agent rotated files since
    (tag mismatch), or the cert is within the refresh threshold.
    """
    if not tag:
        return True
    try:
        if tag != build_tag():
            return True
    except Exception:
        return False
    return svid_expiring_soon(threshold_seconds)


def is_cert_expired_error(exc: BaseException) -> bool:
    """True if an exception chain is an SVID/TLS expiry failure."""
    seen = 0
    cur: Optional[BaseException] = exc
    while cur is not None and seen < 8:
        seen += 1
        name = type(cur).__name__
        msg = str(cur) or ""
        if name == "SSLCertVerificationError" and "has expired" in msg:
            return True
        if "certificate has expired" in msg:
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def start_svid_watcher(
    on_stale: Callable[[], None],
    interval_s: float = 300.0,
    threshold_s: int = REFRESH_THRESHOLD_SECONDS,
) -> threading.Event:
    """Background watchdog: calls `on_stale()` when the SVID needs refresh.

    Intended for :8443 listeners (rebuild server context / graceful restart)
    and long-lived pools. Callback exceptions are logged, never raised.
    Returns a stop Event (set it to terminate the thread).
    """
    stop = threading.Event()

    def _loop() -> None:
        while not stop.wait(interval_s):
            try:
                if _uncached_expiring_soon(threshold_s) or (
                    _svid_files_present() is False and build_tag() != ""
                ):
                    try:
                        on_stale()
                    except Exception as e:
                        logger.warning("svid_watcher_callback_failed error=%s", e)
            except Exception as e:
                logger.warning("svid_watcher_check_failed error=%s", e)

    t = threading.Thread(target=_loop, name="svid-watcher", daemon=True)
    t.start()
    return stop
