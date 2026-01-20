"""
SMS Service Adapter

Unified interface for SMS operations with feature flag routing.
Routes to either legacy products app or new SMS microservice.
"""

from django.conf import settings
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class SMSAdapter:
    """
    Adapter for SMS operations.

    Routes to microservice or legacy code based on feature flag.
    Provides unified interface and automatic fallback.
    """

    def __init__(self):
        self.use_microservice = getattr(
            settings,
            'USE_SMS_MICROSERVICE',
            False  # Default to legacy for safety
        )
        self.fallback_enabled = getattr(
            settings,
            'SMS_MICROSERVICE_FALLBACK',
            True
        )

    def send_sms(
        self,
        to: str,
        message: str,
        account_id: str,
        project_id: Optional[str] = None,
        from_number: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Send SMS via microservice or legacy service.

        Args:
            to: Recipient phone number
            message: SMS message content
            account_id: Account UUID
            project_id: Optional project UUID
            from_number: Optional sender ID
            **kwargs: Additional provider-specific options

        Returns:
            Standardized response:
            {
                'success': bool,
                'sms_id': str,
                'status': str,
                'provider': 'microservice' | 'legacy',
                'data': dict
            }
        """
        if self.use_microservice:
            return self._send_via_microservice(
                to, message, account_id, project_id, from_number, **kwargs
            )
        else:
            return self._send_via_legacy(
                to, message, account_id, project_id, from_number, **kwargs
            )

    def _send_via_microservice(
        self,
        to: str,
        message: str,
        account_id: str,
        project_id: Optional[str],
        from_number: Optional[str],
        **kwargs
    ) -> Dict[str, Any]:
        """Send via SMSLY-SMS microservice."""
        from shared.microservices import get_sms_client, ServiceUnavailableError

        try:
            client = get_sms_client()
            result = client.send_sms(
                to=to,
                message=message,
                account_id=account_id,
                project_id=project_id,
                from_number=from_number,
                **kwargs
            )

            logger.info(f"SMS sent via microservice: {result.get('id')}")

            # Transform to standardized format
            return {
                'success': True,
                'sms_id': result.get('id'),
                'status': result.get('status', 'sent'),
                'provider': 'microservice',
                'data': result
            }

        except ServiceUnavailableError as e:
            logger.error(f"Microservice SMS unavailable: {e}")

            # Fallback to legacy if configured
            if self.fallback_enabled:
                logger.warning("Falling back to legacy SMS service")
                return self._send_via_legacy(
                    to, message, account_id, project_id, from_number, **kwargs
                )

            return {
                'success': False,
                'error': 'SMS service temporarily unavailable',
                'provider': 'microservice'
            }

        except Exception as e:
            logger.error(f"Microservice SMS failed: {e}", exc_info=True)

            # Fallback to legacy if configured
            if self.fallback_enabled:
                logger.warning("Falling back to legacy SMS service after error")
                return self._send_via_legacy(
                    to, message, account_id, project_id, from_number, **kwargs
                )

            return {
                'success': False,
                'error': str(e),
                'provider': 'microservice'
            }

    def _send_via_legacy(
        self,
        to: str,
        message: str,
        account_id: str,
        project_id: Optional[str],
        from_number: Optional[str],
        **kwargs
    ) -> Dict[str, Any]:
        """Send via legacy products app."""
        try:
            from products.services_and_products.sms.service import SMSService

            service = SMSService()
            result = service.send_sms(
                to=to,
                message=message,
                account_id=account_id,
                from_number=from_number,
                **kwargs
            )

            logger.info(f"SMS sent via legacy: {result.get('id')}")

            return {
                'success': True,
                'sms_id': result.get('id'),
                'status': result.get('status'),
                'provider': 'legacy',
                'data': result
            }

        except Exception as e:
            logger.error(f"Legacy SMS failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'provider': 'legacy'
            }

    def get_sms_status(self, sms_id: str) -> Dict[str, Any]:
        """
        Get status of sent SMS.

        Args:
            sms_id: SMS message ID

        Returns:
            SMS status information
        """
        if self.use_microservice:
            return self._get_status_microservice(sms_id)
        else:
            return self._get_status_legacy(sms_id)

    def _get_status_microservice(self, sms_id: str) -> Dict[str, Any]:
        """Get status from microservice."""
        from shared.microservices import get_sms_client

        try:
            client = get_sms_client()
            result = client.get_sms_status(sms_id)
            return {
                'success': True,
                'status': result.get('status'),
                'provider': 'microservice',
                'data': result
            }
        except Exception as e:
            logger.error(f"Failed to get SMS status from microservice: {e}")

            # Fallback to legacy
            if self.fallback_enabled:
                return self._get_status_legacy(sms_id)

            return {
                'success': False,
                'error': str(e),
                'provider': 'microservice'
            }

    def _get_status_legacy(self, sms_id: str) -> Dict[str, Any]:
        """Get status from legacy."""
        try:
            from products.services_and_products.sms.service import SMSService

            service = SMSService()
            result = service.get_status(sms_id)
            return {
                'success': True,
                'status': result.get('status'),
                'provider': 'legacy',
                'data': result
            }
        except Exception as e:
            logger.error(f"Failed to get SMS status from legacy: {e}")
            return {
                'success': False,
                'error': str(e),
                'provider': 'legacy'
            }


# Singleton instance
_sms_adapter = None


def get_sms_adapter() -> SMSAdapter:
    """Get SMS adapter singleton."""
    global _sms_adapter
    if _sms_adapter is None:
        _sms_adapter = SMSAdapter()
    return _sms_adapter
