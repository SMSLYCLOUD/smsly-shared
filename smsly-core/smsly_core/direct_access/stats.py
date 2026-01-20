"""
Direct Access Statistics
=========================
Functions for retrieving direct access attempt statistics.
"""


def get_direct_access_stats(redis_client) -> dict:
    """
    Get statistics about direct access attempts.
    
    Args:
        redis_client: Redis connection
        
    Returns:
        Dict with attempt and blacklist statistics
    """
    try:
        # Count blacklisted IPs
        blacklist_keys = redis_client.keys("direct_access:blacklist:*")
        attempt_keys = redis_client.keys("direct_access:attempts:*")
        
        return {
            "blacklisted_ips": len(blacklist_keys),
            "tracked_ips": len(attempt_keys),
            "blacklist_entries": [
                key.split(":")[-1] for key in blacklist_keys[:100]
            ]
        }
    except Exception as e:
        return {"error": str(e)}
