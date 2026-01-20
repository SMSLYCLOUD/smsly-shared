"""
Password Utilities
==================
Utility functions for password management.
"""

from .hasher import get_cached_hasher


def needs_rehash(hash: str) -> bool:
    """
    Check if a hash needs to be upgraded.
    
    Returns True if:
    - Hash is bcrypt (should migrate to Argon2id)
    - Hash uses outdated Argon2 parameters
    
    Args:
        hash: The hash to check
        
    Returns:
        True if the hash should be re-computed
    """
    if not hash:
        return True
    
    # bcrypt hashes should be upgraded to Argon2id
    if hash.startswith(("$2a$", "$2b$", "$2y$")):
        return True
    
    # Check if Argon2 hash needs parameter upgrade
    if hash.startswith("$argon2"):
        try:
            hasher = get_cached_hasher()
            return hasher.check_needs_rehash(hash)
        except Exception:
            return True
    
    # Unknown format - needs rehash
    return True
