"""
SMSLY Core - Password Hashing
==============================
Async-safe password hashing using Argon2id.

Argon2id is the recommended algorithm for password hashing:
- Winner of the Password Hashing Competition (2015)
- Memory-hard: Resistant to GPU/ASIC attacks
- Configurable: Tune time/memory/parallelism for your hardware
- Async-safe: Runs in thread pool executor

Migration from bcrypt:
- New passwords are hashed with Argon2id
- On login, detect algorithm from hash prefix
- If bcrypt verified, rehash with Argon2id (transparent upgrade)
"""

# Re-export all public APIs for backwards compatibility
from .hasher import get_cached_hasher
from .async_ops import hash_password, verify_password, verify_and_upgrade
from .utils import needs_rehash
from .sync_ops import hash_password_sync, verify_password_sync

__all__ = [
    # Hasher
    "get_cached_hasher",
    # Async Operations
    "hash_password",
    "verify_password",
    "verify_and_upgrade",
    # Utils
    "needs_rehash",
    # Sync Operations
    "hash_password_sync",
    "verify_password_sync",
]
