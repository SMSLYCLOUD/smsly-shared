"""
Password Hasher
===============
Argon2id password hasher configuration and initialization.
"""

from functools import lru_cache


def _get_hasher():
    """Get the Argon2id password hasher with production-ready settings."""
    try:
        from argon2 import PasswordHasher, Type

        # Production settings (~300ms hashing time on typical server)
        return PasswordHasher(
            time_cost=3,        # Number of iterations
            memory_cost=65536,  # 64MB memory (64 * 1024 KB)
            parallelism=4,      # 4 parallel threads
            hash_len=32,        # 32-byte hash output
            salt_len=16,        # 16-byte salt
            type=Type.ID,       # Argon2id variant (best for passwords)
        )
    except ImportError:
        raise ImportError(
            "argon2-cffi is required for password hashing. "
            "Install with: pip install argon2-cffi"
        )


@lru_cache(maxsize=1)
def get_cached_hasher():
    """Get cached hasher instance."""
    return _get_hasher()
