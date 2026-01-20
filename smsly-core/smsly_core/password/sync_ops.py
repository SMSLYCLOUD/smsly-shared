"""
Sync Password Operations
========================
Synchronous password operations for non-async contexts.
"""

from .hasher import get_cached_hasher


def hash_password_sync(password: str) -> str:
    """Synchronous version of hash_password (use async version when possible)."""
    hasher = get_cached_hasher()
    return hasher.hash(password)


def verify_password_sync(password: str, hash: str) -> bool:
    """Synchronous version of verify_password (use async version when possible)."""
    if not password or not hash:
        return False
    
    if hash.startswith("$argon2"):
        try:
            from argon2.exceptions import VerifyMismatchError
            hasher = get_cached_hasher()
            hasher.verify(hash, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False
    elif hash.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            import bcrypt
            return bcrypt.checkpw(
                password.encode("utf-8"),
                hash.encode("utf-8")
            )
        except Exception:
            return False
    
    return False
