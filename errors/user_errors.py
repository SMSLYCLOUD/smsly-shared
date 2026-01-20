"""
User-Facing Error Standards
===========================
Standardized error responses that display friendly messages to users
while logging technical details for debugging.

CRITICAL: Never expose internal error details to end users.
"""

from fastapi import HTTPException
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)


# User-friendly error message
USER_FRIENDLY_MESSAGE = "We are experiencing a configuration issue. Please try again in 30-60 minutes."


def create_user_error(
    internal_code: str,
    log_message: str = None,
    status_code: int = 503,
) -> HTTPException:
    """
    Create a user-friendly HTTPException.
    
    Args:
        internal_code: Internal code for debugging (logged, not shown to user)
        log_message: Technical message for logs
        status_code: HTTP status code (default 503 to indicate temporary issue)
    
    Returns:
        HTTPException with user-friendly message
    """
    if log_message:
        logger.warning(f"[{internal_code}] {log_message}")
    
    return HTTPException(
        status_code=status_code,
        detail={
            "error": "Service temporarily unavailable",
            "message": USER_FRIENDLY_MESSAGE,
            "code": internal_code,
        }
    )


def create_user_error_response(
    internal_code: str,
    log_message: str = None,
    status_code: int = 503,
) -> JSONResponse:
    """
    Create a user-friendly JSONResponse (for Django/non-FastAPI).
    
    Args:
        internal_code: Internal code for debugging
        log_message: Technical message for logs
        status_code: HTTP status code
    
    Returns:
        JSONResponse with user-friendly message
    """
    if log_message:
        logger.warning(f"[{internal_code}] {log_message}")
    
    return JSONResponse(
        status_code=status_code,
        content={
            "error": "Service temporarily unavailable",
            "message": USER_FRIENDLY_MESSAGE,
            "code": internal_code,
        }
    )


# Pre-defined error types for common scenarios
class UserErrors:
    """Standard user error factory methods."""
    
    @staticmethod
    def auth_failed(log_detail: str = None) -> HTTPException:
        """Authentication failed."""
        return create_user_error("AUTH_FAILED", log_detail)
    
    @staticmethod
    def gateway_error(log_detail: str = None) -> HTTPException:
        """Gateway communication error."""
        return create_user_error("GATEWAY_ERROR", log_detail)
    
    @staticmethod
    def service_unavailable(log_detail: str = None) -> HTTPException:
        """Service temporarily unavailable."""
        return create_user_error("SERVICE_UNAVAILABLE", log_detail)
    
    @staticmethod
    def config_error(log_detail: str = None) -> HTTPException:
        """Configuration error."""
        return create_user_error("CONFIG_ERROR", log_detail)
    
    @staticmethod
    def rate_limited(log_detail: str = None) -> HTTPException:
        """Rate limit exceeded."""
        return create_user_error("RATE_LIMITED", log_detail, status_code=429)
    
    @staticmethod
    def permission_denied(log_detail: str = None) -> HTTPException:
        """Permission denied."""
        return create_user_error("PERMISSION_DENIED", log_detail)
