"""
Advanced anomaly detection module for suspicious trading pattern identification.

This module implements sophisticated algorithms to detect various types of
anomalies in trading behavior, market dynamics, and wallet patterns that
may indicate insider trading or market manipulation.
"""

from .algorithms import (
    AnomalyDetectionEngine,
    AnomalyType,
    AnomalyScore,
    WalletBehaviorProfile,
    VolumeAnomalyDetector,
    CoordinatedTradingDetector,
    BehavioralAnomalyDetector,
    MarketManipulationDetector,
    get_anomaly_engine,
    quick_anomaly_scan
)

__all__ = [
    "AnomalyDetectionEngine",
    "AnomalyType",
    "AnomalyScore",
    "WalletBehaviorProfile",
    "VolumeAnomalyDetector",
    "CoordinatedTradingDetector",
    "BehavioralAnomalyDetector",
    "MarketManipulationDetector",
    "get_anomaly_engine",
    "quick_anomaly_scan"
]