"""
Direct Access Statistics
=========================
Functions for retrieving direct access attempt statistics.
"""


def get_direct_access_stats(redis_client, max_keys: int = 10_000) -> dict:
    """
    Get statistics about direct access attempts using non-blocking SCAN.
    
    Args:
        redis_client: Redis connection
        max_keys: Safety cap on scanned keys per prefix
        
    Returns:
        Dict with attempt and blacklist statistics
    """
    try:
        def _scan_prefix(pattern: str) -> list[str]:
            found: list[str] = []
            for raw_key in redis_client.scan_iter(match=pattern, count=200):
                key_str = raw_key.decode("utf-8", errors="replace") if isinstance(raw_key, bytes) else str(raw_key)
                found.append(key_str)
                if len(found) >= max_keys:
                    break
            return found

        blacklist_keys = _scan_prefix("direct_access:blacklist:*")
        attempt_keys = _scan_prefix("direct_access:attempts:*")

        return {
            "blacklisted_ips": len(blacklist_keys),
            "tracked_ips": len(attempt_keys),
            "blacklist_entries": [
                key.split(":")[-1] for key in blacklist_keys[:100]
            ]
        }
    except Exception as e:
        return {"error": str(e)}
