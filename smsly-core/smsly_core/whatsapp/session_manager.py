"""
Session Manager
===============
WhatsApp 24-hour session window management.
"""

from typing import Dict
from datetime import datetime, timedelta

from .models import Session


class SessionManager:
    """
    Manages WhatsApp 24-hour session windows.
    
    Messages outside the session window require templates.
    """
    
    def __init__(self):
        self._sessions: Dict[str, Session] = {}
    
    def get_or_create_session(self, phone: str) -> Session:
        """Get existing session or create new one."""
        if phone in self._sessions:
            session = self._sessions[phone]
            if session.is_active and datetime.utcnow() < session.window_end:
                return session
        
        # Create new session
        now = datetime.utcnow()
        session = Session(
            phone=phone,
            window_start=now,
            window_end=now + timedelta(hours=24),
        )
        self._sessions[phone] = session
        return session
    
    def is_in_session(self, phone: str) -> bool:
        """Check if a phone number is in an active session."""
        if phone not in self._sessions:
            return False
        
        session = self._sessions[phone]
        return session.is_active and datetime.utcnow() < session.window_end
    
    def extend_session(self, phone: str) -> Session:
        """Extend session window on user message."""
        session = self.get_or_create_session(phone)
        
        now = datetime.utcnow()
        session.window_end = now + timedelta(hours=24)
        session.last_message_at = now
        
        return session
    
    def invalidate_session(self, phone: str) -> None:
        """Invalidate a session."""
        if phone in self._sessions:
            self._sessions[phone].is_active = False
