from typing import Optional, Any

class InternalServiceError(Exception):
    """Base exception for all internal service communication errors."""
    def __init__(self, message: str, service: str = "unknown", status_code: Optional[int] = None, details: Any = None):
        self.message = message
        self.service = service
        self.status_code = status_code
        self.details = details
        super().__init__(f"[{service}] {message} (Status: {status_code})")

class ServiceUnavailableError(InternalServiceError):
    """Raised when the target service is unreachable or timing out."""
    pass

class ServiceTimeoutError(ServiceUnavailableError):
    """Raised specifically on timeouts."""
    pass

class AuthenticationError(InternalServiceError):
    """Raised when internal authentication fails (401/403)."""
    pass

class NotFoundError(InternalServiceError):
    """Raised when the requested resource is not found (404)."""
    pass

class ValidationError(InternalServiceError):
    """Raised when the service returns a validation error (422)."""
    pass
