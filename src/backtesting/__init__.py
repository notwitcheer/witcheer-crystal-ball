"""
Backtesting module for strategy validation and optimization.

This module provides comprehensive backtesting capabilities for evaluating
detection algorithms against historical data, optimizing parameters,
and validating strategy performance before live deployment.
"""

from .backtest_engine import (
    BacktestEngine,
    BacktestResults,
    BacktestConfig,
    BacktestAlert,
    BacktestTrade,
    HistoricalDataManager,
    ParameterOptimizer
)

async def get_backtest_engine():
    """Get singleton backtest engine."""
    from ..storage.database import Database
    db = Database()
    return BacktestEngine(db)

__all__ = [
    "BacktestEngine",
    "BacktestResults",
    "BacktestConfig",
    "BacktestAlert",
    "BacktestTrade",
    "HistoricalDataManager",
    "ParameterOptimizer",
    "get_backtest_engine"
]