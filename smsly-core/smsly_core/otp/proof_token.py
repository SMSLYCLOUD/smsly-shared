"""
Proof Token
===========
Generates and verifies cryptographic proof of successful OTP verification.
"""

import time
import base64
import json
import hmac
import hashlib
from typing import Optional


class ProofToken:
    """Generates cryptographic proof of successful verification."""
    
    def __init__(self, secret: str):
        self.secret = secret
    
    def generate(self, session_id: str, phone_hash: str) -> str:
        """
        Generate a proof token for a verified session.
        
        Args:
            session_id: Verified session ID
            phone_hash: Hashed phone number
            
        Returns:
            Signed proof token
        """
        payload = {
            "sid": session_id,
            "ph": phone_hash[:16],  # Truncated for privacy
            "ts": int(time.time()),
            "ver": "1",
        }
        
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()
        
        signature = hmac.new(
            self.secret.encode(),
            payload_b64.encode(),
            hashlib.sha256,
        ).hexdigest()[:32]
        
        return f"{payload_b64}.{signature}"
    
    def verify(self, token: str, max_age_seconds: int = 3600) -> Optional[dict]:
        """
        Verify a proof token.
        
        Args:
            token: The proof token
            max_age_seconds: Maximum token age
            
        Returns:
            Payload if valid, None otherwise
        """
        try:
            parts = token.split('.')
            if len(parts) != 2:
                return None
            
            payload_b64, signature = parts
            
            # Verify signature
            expected_sig = hmac.new(
                self.secret.encode(),
                payload_b64.encode(),
                hashlib.sha256,
            ).hexdigest()[:32]
            
            if not hmac.compare_digest(signature, expected_sig):
                return None
            
            # Decode payload
            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
            payload = json.loads(payload_json)
            
            # Check expiry
            if time.time() - payload.get("ts", 0) > max_age_seconds:
                return None
            
            return payload
        except Exception:
            return None
