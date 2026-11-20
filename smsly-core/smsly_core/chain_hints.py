"""Deterministic per-chain variable 2-point hash hint and commitment helpers."""

from __future__ import annotations

import hashlib
from typing import Any


def compute_prev_hash_hint(
    prev_hash: str,
    *,
    current_link_id: str,
    prev_link_id: str = "",
    channel: str = "email",
) -> dict[str, Any]:
    """Compute deterministic, non-overlapping 2-point hash slices seeded by link IDs."""
    clean = str(prev_hash or "").strip().lower()
    if clean.startswith("0x"):
        clean = clean[2:]
    n = len(clean)
    if not clean:
        return {}
    if n < 12:
        w = min(2, max(1, n // 3))
        s1, e1 = 0, w
        s2, e2 = max(e1, n - w), n
    else:
        w = 4 if n >= 24 else 2
        half = n // 2
        left_span = max(1, half - w)
        right_min = min(n - w, half + 1)
        right_span = max(1, (n - w) - right_min + 1)
        seed = (
            f"trulay-hint-v2:{str(channel or 'email').strip().lower()}:"
            f"{str(current_link_id or '').strip().lower()}:"
            f"{str(prev_link_id or '').strip().lower()}"
        )
        digest = hashlib.sha256(seed.encode("utf-8")).digest()
        s1 = int.from_bytes(digest[0:4], "big") % left_span
        e1 = s1 + w
        s2 = right_min + (int.from_bytes(digest[4:8], "big") % right_span)
        e2 = s2 + w
    masked = ["•"] * n
    masked[s1:e1] = list(clean[s1:e1])
    masked[s2:e2] = list(clean[s2:e2])
    return {
        "prev_hint_mode": "dual-slice-v2",
        "prev_hash_len": n,
        "prev_hint_slices": [
            {"start": s1, "end": e1, "value": clean[s1:e1]},
            {"start": s2, "end": e2, "value": clean[s2:e2]},
        ],
        "prev_hash_masked": "".join(masked),
    }


def build_prev_commitments(*candidates: str | None) -> list[str]:
    """Return deduplicated salted SHA-256 commitments for normalized candidate strings."""
    out: list[str] = []
    for cand in candidates:
        if cand is None:
            continue
        norm = str(cand).strip().lower()
        if not norm:
            continue
        if norm.startswith("0x") and len(norm) == 66 and all(c in "0123456789abcdef" for c in norm[2:]):
            norm = norm[2:]
        digest = hashlib.sha256(f"trulay-prev-comm-v1:{norm}".encode("utf-8")).hexdigest()
        if digest not in out:
            out.append(digest)
    return out
