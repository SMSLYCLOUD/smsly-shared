"""
Tests for SMS Adapter

Verifies feature flag routing, fallback behavior, and error handling.
"""

from django.test import TestCase, override_settings
from unittest.mock import patch, MagicMock
from shared.adapters.sms_adapter import get_sms_adapter, SMSAdapter


class SMSAdapterTestCase(TestCase):
    """Test SMS adapter routing and fallback."""

    def setUp(self):
        """Reset singleton between tests."""
        import shared.adapters.sms_adapter
        shared.adapters.sms_adapter._sms_adapter = None

    @override_settings(USE_SMS_MICROSERVICE=False)
    def test_uses_legacy_when_flag_disabled(self):
        """Test adapter routes to legacy when feature flag=False."""
        adapter = get_sms_adapter()
        self.assertFalse(adapter.use_microservice)

    @override_settings(USE_SMS_MICROSERVICE=True)
    def test_uses_microservice_when_flag_enabled(self):
        """Test adapter routes to microservice when feature flag=True."""
        adapter = get_sms_adapter()
        self.assertTrue(adapter.use_microservice)

    @override_settings(
        USE_SMS_MICROSERVICE=False,
        SMS_MICROSERVICE_FALLBACK=True
    )
    @patch('products.services_and_products.sms.service.SMSService')
    def test_send_via_legacy(self, mock_service):
        """Test sending SMS via legacy products app."""
        # Mock legacy service
        mock_instance = MagicMock()
        mock_instance.send_sms.return_value = {
            'id': 'sms-123',
            'status': 'sent'
        }
        mock_service.return_value = mock_instance

        # Send SMS
        adapter = get_sms_adapter()
        result = adapter.send_sms(
            to="+15555555555",
            message="Test message",
            account_id="account-uuid"
        )

        # Verify
        self.assertTrue(result['success'])
        self.assertEqual(result['provider'], 'legacy')
        self.assertEqual(result['sms_id'], 'sms-123')
        mock_instance.send_sms.assert_called_once()

    @override_settings(
        USE_SMS_MICROSERVICE=True,
        SMS_MICROSERVICE_FALLBACK=True
    )
    @patch('shared.microservices.get_sms_client')
    def test_send_via_microservice(self, mock_get_client):
        """Test sending SMS via microservice."""
        # Mock microservice client
        mock_client = MagicMock()
        mock_client.send_sms.return_value = {
            'id': 'sms-456',
            'status': 'queued'
        }
        mock_get_client.return_value = mock_client

        # Send SMS
        adapter = get_sms_adapter()
        result = adapter.send_sms(
            to="+15555555555",
            message="Test message",
            account_id="account-uuid",
            project_id="project-uuid"
        )

        # Verify
        self.assertTrue(result['success'])
        self.assertEqual(result['provider'], 'microservice')
        self.assertEqual(result['sms_id'], 'sms-456')
        mock_client.send_sms.assert_called_once()

    @override_settings(
        USE_SMS_MICROSERVICE=True,
        SMS_MICROSERVICE_FALLBACK=True
    )
    @patch('shared.microservices.get_sms_client')
    @patch('products.services_and_products.sms.service.SMSService')
    def test_fallback_on_microservice_failure(self, mock_legacy_service, mock_get_client):
        """Test automatic fallback to legacy when microservice fails."""
        # Mock microservice failure
        from shared.microservices import ServiceUnavailableError
        mock_client = MagicMock()
        mock_client.send_sms.side_effect = ServiceUnavailableError("Service down")
        mock_get_client.return_value = mock_client

        # Mock legacy success
        mock_legacy_instance = MagicMock()
        mock_legacy_instance.send_sms.return_value = {
            'id': 'sms-fallback',
            'status': 'sent'
        }
        mock_legacy_service.return_value = mock_legacy_instance

        # Send SMS (should fallback)
        adapter = get_sms_adapter()
        result = adapter.send_sms(
            to="+15555555555",
            message="Test message",
            account_id="account-uuid"
        )

        # Verify fallback occurred
        self.assertTrue(result['success'])
        self.assertEqual(result['provider'], 'legacy')  # Fell back!
        self.assertEqual(result['sms_id'], 'sms-fallback')
        mock_client.send_sms.assert_called_once()  # Tried microservice
        mock_legacy_instance.send_sms.assert_called_once()  # Fell back

    @override_settings(
        USE_SMS_MICROSERVICE=True,
        SMS_MICROSERVICE_FALLBACK=False  # No fallback
    )
    @patch('shared.microservices.get_sms_client')
    def test_no_fallback_when_disabled(self, mock_get_client):
        """Test error returned when microservice fails and fallback disabled."""
        # Mock microservice failure
        from shared.microservices import ServiceUnavailableError
        mock_client = MagicMock()
        mock_client.send_sms.side_effect = ServiceUnavailableError("Service down")
        mock_get_client.return_value = mock_client

        # Send SMS (should fail, no fallback)
        adapter = get_sms_adapter()
        result = adapter.send_sms(
            to="+15555555555",
            message="Test message",
            account_id="account-uuid"
        )

        # Verify error returned
        self.assertFalse(result['success'])
        self.assertEqual(result['provider'], 'microservice')
        self.assertIn('error', result)

    @override_settings(USE_SMS_MICROSERVICE=False)
    @patch('products.services_and_products.sms.service.SMSService')
    def test_get_status_legacy(self, mock_service):
        """Test getting SMS status from legacy."""
        # Mock legacy service
        mock_instance = MagicMock()
        mock_instance.get_status.return_value = {
            'status': 'delivered'
        }
        mock_service.return_value = mock_instance

        # Get status
        adapter = get_sms_adapter()
        result = adapter.get_sms_status('sms-123')

        # Verify
        self.assertTrue(result['success'])
        self.assertEqual(result['status'], 'delivered')
        self.assertEqual(result['provider'], 'legacy')

    @override_settings(USE_SMS_MICROSERVICE=True)
    @patch('shared.microservices.get_sms_client')
    def test_get_status_microservice(self, mock_get_client):
        """Test getting SMS status from microservice."""
        # Mock microservice
        mock_client = MagicMock()
        mock_client.get_sms_status.return_value = {
            'status': 'sent'
        }
        mock_get_client.return_value = mock_client

        # Get status
        adapter = get_sms_adapter()
        result = adapter.get_sms_status('sms-456')

        # Verify
        self.assertTrue(result['success'])
        self.assertEqual(result['status'], 'sent')
        self.assertEqual(result['provider'], 'microservice')

    def test_singleton_pattern(self):
        """Test adapter uses singleton pattern."""
        adapter1 = get_sms_adapter()
        adapter2 = get_sms_adapter()
        self.assertIs(adapter1, adapter2)  # Same instance
