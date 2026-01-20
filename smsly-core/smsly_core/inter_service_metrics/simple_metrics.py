"""
Simple Metrics Fallback
=======================
In-memory metrics for when prometheus_client is not available.
"""

import asyncio
from typing import Dict, Any


class SimpleInterServiceMetrics:
    """Simple in-memory metrics when prometheus_client is not available."""
    
    def __init__(self):
        self._latencies: Dict[str, list] = {}
        self._counts: Dict[str, int] = {}
        self._lock = asyncio.Lock()
    
    async def record_latency(
        self,
        source: str,
        target: str,
        method: str,
        endpoint: str,
        status: str,
        duration: float,
    ):
        async with self._lock:
            key = f"{source}:{target}:{method}:{endpoint}:{status}"
            if key not in self._latencies:
                self._latencies[key] = []
            self._latencies[key].append(duration)
            
            # Keep only last 1000 samples
            if len(self._latencies[key]) > 1000:
                self._latencies[key] = self._latencies[key][-1000:]
            
            # Count
            self._counts[key] = self._counts.get(key, 0) + 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get aggregated statistics."""
        stats = {}
        for key, values in self._latencies.items():
            if values:
                sorted_values = sorted(values)
                stats[key] = {
                    "count": len(values),
                    "avg_ms": sum(values) / len(values) * 1000,
                    "p50_ms": sorted_values[len(values) // 2] * 1000,
                    "p95_ms": sorted_values[int(len(values) * 0.95)] * 1000,
                    "p99_ms": sorted_values[int(len(values) * 0.99)] * 1000,
                }
        return stats


# Global simple metrics instance
_simple_metrics = SimpleInterServiceMetrics()


def get_simple_metrics() -> SimpleInterServiceMetrics:
    """Get the global simple metrics instance."""
    return _simple_metrics
