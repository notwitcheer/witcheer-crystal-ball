"""
Clustering module for detecting coordinated wallet activity.

This module provides advanced algorithms for identifying groups of wallets
that exhibit coordinated behavior patterns, helping detect insider trading
rings and market manipulation schemes.
"""

from .wallet_clustering import (
    WalletClusteringEngine,
    WalletCluster,
    TradingBehavior,
    BehaviorAnalyzer,
    CoordinationDetector,
    get_clustering_engine
)

__all__ = [
    "WalletClusteringEngine",
    "WalletCluster",
    "TradingBehavior",
    "BehaviorAnalyzer",
    "CoordinationDetector",
    "get_clustering_engine"
]