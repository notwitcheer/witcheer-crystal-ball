"""
Performance tracking module for monitoring strategy effectiveness and ROI.

This module provides comprehensive performance tracking capabilities for
monitoring the effectiveness of detection signals, calculating returns,
and generating insights for strategy optimization.
"""

from .tracker import (
    PerformanceTracker,
    PerformanceMetrics,
    AlertPerformance,
    get_performance_tracker
)

__all__ = [
    "PerformanceTracker",
    "PerformanceMetrics",
    "AlertPerformance",
    "get_performance_tracker"
]