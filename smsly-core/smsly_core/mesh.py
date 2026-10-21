"""
Mesh URL helpers.
================

The PaaS injects service URLs into every container. A subset of those
values uses the ``<service>.internal`` placeholder form, which resolves
to the edge router (Traefik/Caddy) instead of the service container. The
edge has no route for those hosts, so the request never reaches the
microservice — it lands on the catch-all page (HTTP 200/503 HTML) or is
refused.

A placeholder is therefore *worse than no value at all*: it silently
turns a service call into a bogus edge call. These helpers detect and
reject placeholders so callers can fall back to a working route.

Usage::

    from smsly_core.mesh import is_placeholder_mesh_url
    if is_placeholder_mesh_url(url):
        url = fallback
"""

from __future__ import annotations

from urllib.parse import urlparse

# Host suffixes that identify a placeholder (edge) address rather than a
# real service address.
PLACEHOLDER_HOST_SUFFIXES = (
    ".internal",
    ".edge",
    ".placeholder",
)


def _host_of(url: str) -> str:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return ""
    return host


def is_placeholder_mesh_url(url: str | None) -> bool:
    """True when `url` points at an edge placeholder, not a real service."""
    if not url:
        return True
    host = _host_of(url)
    if not host:
        # No host at all (e.g. a bare path) is not a usable service URL.
        return True
    return any(host.endswith(sfx) for sfx in PLACEHOLDER_HOST_SUFFIXES)


def is_internal_mesh_url(url: str | None) -> bool:
    """True when `url` addresses a service inside the private mesh.

    Internal addresses are either single-label service hosts
    (``smsly-email``) or hosts under an internal suffix. Public edge
    hostnames (``*.trulay.site``) are not internal.
    """
    if not url:
        return False
    host = _host_of(url)
    if not host:
        return False
    if "." not in host:
        return True
    return any(host.endswith(sfx) for sfx in PLACEHOLDER_HOST_SUFFIXES)


__all__ = [
    "PLACEHOLDER_HOST_SUFFIXES",
    "is_placeholder_mesh_url",
    "is_internal_mesh_url",
]
