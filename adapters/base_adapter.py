"""
Base Adapter

Foundation class for all service adapters.
"""

from typing import Dict, Any
from django.conf import settings
import logging
import time

logger = logging.getLogger(__name__)


class BaseAdapter:
    """
    Base class for service adapters.

    Provides common functionality:
    - Feature flag checking
    - Metrics tracking
    - Error handling patterns
    """

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.use_microservice = self._get_feature_flag()
        self.fallback_enabled = self._get_fallback_flag()

    def _get_feature_flag(self) -> bool:
        """Get feature flag for this service."""
        flag_name = f'USE_{self.service_name.upper()}_MICROSERVICE'
        return getattr(settings, flag_name, False)

    def _get_fallback_flag(self) -> bool:
        """Get fallback flag for this service."""
        flag_name = f'{self.service_name.upper()}_MICROSERVICE_FALLBACK'
        return getattr(settings, flag_name, True)

    def _track_request(
        self,
        operation: str,
        provider: str,
        success: bool,
        duration: float,
        **metadata
    ):
        """
        Track adapter request metrics.

        Args:
            operation: Operation name (e.g., 'send_sms')
            provider: 'microservice' or 'legacy'
            success: Whether operation succeeded
            duration: Duration in seconds
            **metadata: Additional metadata
        """
        try:
            from core.metrics import track_metric

            track_metric('adapter.request', {
                'service': self.service_name,
                'operation': operation,
                'provider': provider,
                'success': success,
                'duration_ms': duration * 1000,
                **metadata
            })
        except Exception as e:
            logger.warning(f"Failed to track metrics: {e}")

    def _execute_with_tracking(
        self,
        operation: str,
        func,
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute function with automatic tracking.

        Args:
            operation: Operation name
            func: Function to execute
            *args, **kwargs: Function arguments

        Returns:
            Function result with 'provider' key added
        """
        start_time = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start_time

        self._track_request(
            operation=operation,
            provider=result.get('provider', 'unknown'),
            success=result.get('success', False),
            duration=duration
        )

        return result
