"""
Prometheus Metrics
===================
Common metrics for SMSLY microservices.
"""

from typing import Dict, Optional
from dataclasses import dataclass, field
from time import time
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class MetricLabels:
    """Common labels for metrics."""
    service: str
    environment: str = "production"
    version: str = "1.0.0"


class SimpleMetrics:
    """
    Simple in-memory metrics collector.
    
    For production, use prometheus_client with pushgateway.
    """
    
    def __init__(self, labels: Optional[MetricLabels] = None):
        self.labels = labels or MetricLabels(service="unknown")
        self._counters: Dict[str, int] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, list] = {}
    
    def increment(self, name: str, value: int = 1, labels: Optional[Dict] = None) -> None:
        """Increment a counter."""
        key = self._make_key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict] = None) -> None:
        """Set a gauge value."""
        key = self._make_key(name, labels)
        self._gauges[key] = value
    
    def observe(self, name: str, value: float, labels: Optional[Dict] = None) -> None:
        """Record a histogram observation."""
        key = self._make_key(name, labels)
        if key not in self._histograms:
            self._histograms[key] = []
        self._histograms[key].append(value)
    
    def _make_key(self, name: str, labels: Optional[Dict] = None) -> str:
        """Create a unique key for a metric."""
        if labels:
            label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
            return f"{name}{{{label_str}}}"
        return name
    
    def get_counter(self, name: str, labels: Optional[Dict] = None) -> int:
        """Get counter value."""
        return self._counters.get(self._make_key(name, labels), 0)
    
    def get_histogram_stats(self, name: str, labels: Optional[Dict] = None) -> Dict:
        """Get histogram statistics."""
        key = self._make_key(name, labels)
        values = self._histograms.get(key, [])
        
        if not values:
            return {"count": 0, "sum": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0}
        
        sorted_values = sorted(values)
        count = len(values)
        
        return {
            "count": count,
            "sum": sum(values),
            "avg": sum(values) / count,
            "p50": self._percentile(sorted_values, 50),
            "p95": self._percentile(sorted_values, 95),
            "p99": self._percentile(sorted_values, 99),
        }
    
    def _percentile(self, sorted_values: list, percentile: int) -> float:
        """Calculate percentile from sorted values."""
        if not sorted_values:
            return 0
        idx = int(len(sorted_values) * percentile / 100)
        return sorted_values[min(idx, len(sorted_values) - 1)]
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = []
        
        # Labels
        base_labels = f'service="{self.labels.service}",env="{self.labels.environment}"'
        
        # Counters
        for key, value in self._counters.items():
            name = key.split('{')[0]
            extra_labels = key[len(name):] if '{' in key else ''
            full_labels = f'{{{base_labels}{"," + extra_labels[1:-1] if extra_labels else ""}}}'
            lines.append(f'{name}_total{full_labels} {value}')
        
        # Gauges
        for key, value in self._gauges.items():
            name = key.split('{')[0]
            extra_labels = key[len(name):] if '{' in key else ''
            full_labels = f'{{{base_labels}{"," + extra_labels[1:-1] if extra_labels else ""}}}'
            lines.append(f'{name}{full_labels} {value}')
        
        # Histograms (simplified as summary)
        for key in self._histograms:
            stats = self.get_histogram_stats(key.split('{')[0])
            name = key.split('{')[0]
            lines.append(f'{name}_count{{{base_labels}}} {stats["count"]}')
            lines.append(f'{name}_sum{{{base_labels}}} {stats["sum"]}')
        
        return '\n'.join(lines)


class Timer:
    """Context manager for timing operations."""
    
    def __init__(self, metrics: SimpleMetrics, name: str, labels: Optional[Dict] = None):
        self.metrics = metrics
        self.name = name
        self.labels = labels
        self._start: Optional[float] = None
    
    def __enter__(self):
        self._start = time()
        return self
    
    def __exit__(self, *args):
        if self._start:
            duration = time() - self._start
            self.metrics.observe(self.name, duration, self.labels)


# Pre-defined metric names
class MetricNames:
    # Request metrics
    HTTP_REQUESTS_TOTAL = "http_requests"
    HTTP_REQUEST_DURATION = "http_request_duration_seconds"
    HTTP_REQUEST_SIZE = "http_request_size_bytes"
    HTTP_RESPONSE_SIZE = "http_response_size_bytes"
    
    # Messaging metrics
    MESSAGES_SENT_TOTAL = "smsly_messages_sent"
    MESSAGES_DELIVERED_TOTAL = "smsly_messages_delivered"
    MESSAGES_FAILED_TOTAL = "smsly_messages_failed"
    MESSAGE_SEND_DURATION = "smsly_message_send_duration_seconds"
    
    # Queue metrics
    QUEUE_DEPTH = "smsly_queue_depth"
    QUEUE_PROCESSING_TIME = "smsly_queue_processing_seconds"
    
    # Database metrics
    DB_CONNECTIONS_ACTIVE = "smsly_db_connections_active"
    DB_QUERY_DURATION = "smsly_db_query_duration_seconds"
    
    # Rate limiting metrics
    RATE_LIMIT_HITS = "smsly_rate_limit_hits"
    RATE_LIMIT_ALLOWED = "smsly_rate_limit_allowed"
