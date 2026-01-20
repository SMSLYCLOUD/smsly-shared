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
- On login, detect algorithm from hash prefix:
  - $2a$, $2b$, $2y$ → bcrypt
  - $argon2id$ → Argon2id
- If bcrypt verified, rehash with Argon2id (transparent upgrade)
"""

import asyncio
from typing import Tuple, Optional
from functools import lru_cache


# Lazy import to avoid startup cost if not used
def _get_hasher():
    """Get the Argon2id password hasher with production-ready settings."""
    try:
        from argon2 import PasswordHasher, Type
        from argon2.profiles import RFC_9106_LOW_MEMORY

        # Production settings (adjust based on your server specs)
        # These settings provide ~300ms hashing time on a typical server
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
def _get_cached_hasher():
    """Cached hasher instance."""
    return _get_hasher()


async def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        Argon2id hash string (includes algorithm, parameters, salt, and hash)
        
    Example:
        >>> hash = await hash_password("my_secure_password")
        >>> print(hash[:10])
        '$argon2id$'
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    hasher = _get_cached_hasher()
    loop = asyncio.get_event_loop()
    
    # Run in executor to avoid blocking the event loop
    return await loop.run_in_executor(None, hasher.hash, password)


async def verify_password(password: str, hash: str) -> bool:
    """
    Verify a password against an Argon2id or bcrypt hash.
    
    Supports both Argon2id and bcrypt hashes for migration compatibility.
    
    Args:
        password: Plain text password to verify
        hash: Hash to verify against (Argon2id or bcrypt format)
        
    Returns:
        True if password matches, False otherwise
    """
    if not password or not hash:
        return False
    
    loop = asyncio.get_event_loop()
    
    # Detect hash type from prefix
    if hash.startswith("$argon2"):
        # Argon2 hash
        return await _verify_argon2(password, hash, loop)
    elif hash.startswith(("$2a$", "$2b$", "$2y$")):
        # bcrypt hash (legacy compatibility)
        return await _verify_bcrypt(password, hash, loop)
    else:
        # Unknown format
        return False


async def _verify_argon2(password: str, hash: str, loop) -> bool:
    """Verify Argon2 hash."""
    try:
        from argon2.exceptions import VerifyMismatchError, InvalidHashError
        
        hasher = _get_cached_hasher()
        
        def _verify():
            try:
                hasher.verify(hash, password)
                return True
            except VerifyMismatchError:
                return False
            except InvalidHashError:
                return False
        
        return await loop.run_in_executor(None, _verify)
    except ImportError:
        return False


async def _verify_bcrypt(password: str, hash: str, loop) -> bool:
    """Verify bcrypt hash (legacy compatibility)."""
    try:
        import bcrypt
        
        def _verify():
            try:
                return bcrypt.checkpw(password.encode("utf-8"), hash.encode("utf-8"))
            except Exception:
                return False
        
        return await loop.run_in_executor(None, _verify)
    except ImportError:
        # bcrypt not installed - can't verify legacy hashes
        return False


def needs_rehash(hash: str) -> bool:
    """
    Check if a hash needs to be upgraded.
    
    Returns True if:
    - Hash is bcrypt (should migrate to Argon2id)
    - Hash uses outdated Argon2 parameters
    
    Args:
        hash: The hash to check
        
    Returns:
        True if the hash should be re-computed, False otherwise
    """
    if not hash:
        return True
    
    # bcrypt hashes should be upgraded to Argon2id
    if hash.startswith(("$2a$", "$2b$", "$2y$")):
        return True
    
    # Check if Argon2 hash needs parameter upgrade
    if hash.startswith("$argon2"):
        try:
            hasher = _get_cached_hasher()
            return hasher.check_needs_rehash(hash)
        except Exception:
            return True
    
    # Unknown format - needs rehash
    return True


async def verify_and_upgrade(
    password: str,
    hash: str,
) -> Tuple[bool, Optional[str]]:
    """
    Verify password and return new hash if upgrade is needed.
    
    This is the recommended function for login flows. It:
    1. Verifies the password against the existing hash
    2. If valid and hash needs upgrade, returns new Argon2id hash
    
    Args:
        password: Plain text password
        hash: Existing hash (bcrypt or Argon2id)
        
    Returns:
        Tuple of (is_valid, new_hash_or_none)
        - is_valid: True if password is correct
        - new_hash: New Argon2id hash if upgrade needed, None otherwise
        
    Example:
        >>> valid, new_hash = await verify_and_upgrade(password, stored_hash)
        >>> if valid:
        >>>     if new_hash:
        >>>         await update_user_password_hash(user_id, new_hash)
        >>>     # Continue with login
    """
    is_valid = await verify_password(password, hash)
    
    if not is_valid:
        return False, None
    
    # Check if upgrade is needed
    if needs_rehash(hash):
        new_hash = await hash_password(password)
        return True, new_hash
    
    return True, None


# Convenience sync wrappers for non-async contexts
def hash_password_sync(password: str) -> str:
    """Synchronous version of hash_password (use async version when possible)."""
    hasher = _get_cached_hasher()
    return hasher.hash(password)


def verify_password_sync(password: str, hash: str) -> bool:
    """Synchronous version of verify_password (use async version when possible)."""
    if not password or not hash:
        return False
    
    if hash.startswith("$argon2"):
        try:
            from argon2.exceptions import VerifyMismatchError
            hasher = _get_cached_hasher()
            hasher.verify(hash, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False
    elif hash.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode("utf-8"), hash.encode("utf-8"))
        except Exception:
            return False
    
    return False
