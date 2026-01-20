"""
Async Password Hashing
======================
Async-safe password hashing and verification using Argon2id.
"""

import asyncio
from typing import Tuple, Optional

from .hasher import get_cached_hasher


async def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        Argon2id hash string (includes algorithm, parameters, salt, and hash)
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    hasher = get_cached_hasher()
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
        return await _verify_argon2(password, hash, loop)
    elif hash.startswith(("$2a$", "$2b$", "$2y$")):
        return await _verify_bcrypt(password, hash, loop)
    else:
        return False


async def _verify_argon2(password: str, hash: str, loop) -> bool:
    """Verify Argon2 hash."""
    try:
        from argon2.exceptions import VerifyMismatchError, InvalidHashError
        
        hasher = get_cached_hasher()
        
        def _verify():
            try:
                hasher.verify(hash, password)
                return True
            except (VerifyMismatchError, InvalidHashError):
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
                return bcrypt.checkpw(
                    password.encode("utf-8"),
                    hash.encode("utf-8")
                )
            except Exception:
                return False
        
        return await loop.run_in_executor(None, _verify)
    except ImportError:
        return False


async def verify_and_upgrade(
    password: str,
    hash: str,
) -> Tuple[bool, Optional[str]]:
    """
    Verify password and return new hash if upgrade is needed.
    
    This is the recommended function for login flows.
    
    Args:
        password: Plain text password
        hash: Existing hash (bcrypt or Argon2id)
        
    Returns:
        Tuple of (is_valid, new_hash_or_none)
    """
    is_valid = await verify_password(password, hash)
    
    if not is_valid:
        return False, None
    
    # Check if upgrade is needed
    from .utils import needs_rehash
    if needs_rehash(hash):
        new_hash = await hash_password(password)
        return True, new_hash
    
    return True, None
