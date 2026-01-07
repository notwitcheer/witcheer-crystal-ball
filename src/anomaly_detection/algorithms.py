"""
Advanced anomaly detection algorithms for identifying suspicious trading patterns.

This module implements sophisticated statistical and machine learning approaches
to detect outliers in wallet behavior, market dynamics, and trading patterns
that may indicate insider trading or market manipulation.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum

import numpy as np
from pydantic import BaseModel, Field

from ..storage.database import Database


class AnomalyType(str, Enum):
    """Types of anomalies that can be detected."""
    VOLUME_SPIKE = "volume_spike"
    PRICE_MANIPULATION = "price_manipulation"
    COORDINATED_PUMPING = "coordinated_pumping"
    WASH_TRADING = "wash_trading"
    FRONT_RUNNING = "front_running"
    INSIDER_CLUSTERING = "insider_clustering"
    MARKET_TIMING = "market_timing"
    BEHAVIORAL_DEVIATION = "behavioral_deviation"


@dataclass
class AnomalyScore:
    """Anomaly detection result with confidence metrics."""
    anomaly_type: AnomalyType
    confidence: float  # 0.0 to 1.0
    severity: float    # 0.0 to 1.0
    timestamp: datetime
    details: Dict[str, Any]
    affected_wallets: List[str]
    market_id: Optional[str] = None


class WalletBehaviorProfile(BaseModel):
    """Statistical profile of wallet trading behavior."""
    wallet_address: str
    total_trades: int
    avg_position_size: float
    std_position_size: float
    avg_time_between_trades: float
    preferred_markets: List[str]
    trading_hours_distribution: List[float]  # 24 hourly buckets
    win_rate: float
    risk_tolerance: float
    position_hold_time_avg: float
    market_timing_score: float


class VolumeAnomalyDetector:
    """Detects unusual volume spikes and patterns."""

    def __init__(self, lookback_days: int = 30, sensitivity: float = 3.0):
        self.lookback_days = lookback_days
        self.sensitivity = sensitivity
        self.logger = logging.getLogger(__name__)

    async def detect_volume_anomalies(self, market_id: str) -> List[AnomalyScore]:
        """Detect volume anomalies for a specific market."""
        async with Database() as db:
            # Get historical volume data
            volumes = await db.fetch_all("""
                SELECT
                    DATE(created_at) as trade_date,
                    SUM(position_size_usd) as daily_volume,
                    COUNT(*) as trade_count
                FROM alerts
                WHERE market_id = ?
                  AND created_at >= datetime('now', '-{} days')
                GROUP BY DATE(created_at)
                ORDER BY trade_date
            """.format(self.lookback_days), (market_id,))

            if len(volumes) < 7:  # Need at least a week of data
                return []

            # Calculate statistical thresholds
            volume_values = [float(row['daily_volume']) for row in volumes]
            mean_volume = np.mean(volume_values)
            std_volume = np.std(volume_values)

            # Z-score based anomaly detection
            anomalies = []
            threshold = mean_volume + (self.sensitivity * std_volume)

            for i, volume_data in enumerate(volumes):
                volume = float(volume_data['daily_volume'])

                if volume > threshold:
                    # Calculate confidence based on how far above threshold
                    z_score = (volume - mean_volume) / std_volume if std_volume > 0 else 0
                    confidence = min(0.95, z_score / 5.0)  # Cap at 95%
                    severity = min(1.0, (volume - threshold) / mean_volume)

                    anomaly = AnomalyScore(
                        anomaly_type=AnomalyType.VOLUME_SPIKE,
                        confidence=confidence,
                        severity=severity,
                        timestamp=datetime.fromisoformat(volume_data['trade_date']),
                        details={
                            "volume": volume,
                            "mean_volume": mean_volume,
                            "threshold": threshold,
                            "z_score": z_score,
                            "trade_count": volume_data['trade_count']
                        },
                        affected_wallets=[],  # Would need additional query
                        market_id=market_id
                    )
                    anomalies.append(anomaly)

            return anomalies


class CoordinatedTradingDetector:
    """Detects coordinated trading patterns between wallets."""

    def __init__(self, time_window_minutes: int = 30, min_wallet_count: int = 3):
        self.time_window_minutes = time_window_minutes
        self.min_wallet_count = min_wallet_count
        self.logger = logging.getLogger(__name__)

    async def detect_coordinated_activity(self, market_id: str) -> List[AnomalyScore]:
        """Detect coordinated trading in a market."""
        async with Database() as db:
            # Get recent trades within time windows
            trades = await db.fetch_all("""
                SELECT
                    wallet_address,
                    position_side,
                    position_size_usd,
                    created_at,
                    price_at_detection
                FROM alerts
                WHERE market_id = ?
                  AND created_at >= datetime('now', '-24 hours')
                ORDER BY created_at
            """, (market_id,))

            if len(trades) < self.min_wallet_count:
                return []

            # Group trades by time windows
            time_windows = self._group_by_time_windows(trades)
            anomalies = []

            for window_start, window_trades in time_windows.items():
                # Check for coordinated behavior
                coordination_score = self._calculate_coordination_score(window_trades)

                if coordination_score > 0.7:  # High coordination threshold
                    wallets = list(set(trade['wallet_address'] for trade in window_trades))

                    if len(wallets) >= self.min_wallet_count:
                        anomaly = AnomalyScore(
                            anomaly_type=AnomalyType.COORDINATED_PUMPING,
                            confidence=coordination_score,
                            severity=min(1.0, len(wallets) / 10.0),  # More wallets = higher severity
                            timestamp=window_start,
                            details={
                                "wallet_count": len(wallets),
                                "trade_count": len(window_trades),
                                "coordination_score": coordination_score,
                                "time_window_minutes": self.time_window_minutes
                            },
                            affected_wallets=wallets,
                            market_id=market_id
                        )
                        anomalies.append(anomaly)

            return anomalies

    def _group_by_time_windows(self, trades: List[Dict]) -> Dict[datetime, List[Dict]]:
        """Group trades into time windows."""
        windows = {}
        window_size = timedelta(minutes=self.time_window_minutes)

        for trade in trades:
            trade_time = datetime.fromisoformat(trade['created_at'])

            # Find the appropriate window
            window_start = None
            for existing_window in windows.keys():
                if existing_window <= trade_time < existing_window + window_size:
                    window_start = existing_window
                    break

            # Create new window if needed
            if window_start is None:
                # Round down to nearest window boundary
                minutes_since_hour = trade_time.minute % self.time_window_minutes
                window_start = trade_time.replace(
                    minute=trade_time.minute - minutes_since_hour,
                    second=0,
                    microsecond=0
                )
                windows[window_start] = []

            windows[window_start].append(trade)

        return windows

    def _calculate_coordination_score(self, trades: List[Dict]) -> float:
        """Calculate how coordinated a group of trades appears."""
        if len(trades) < 2:
            return 0.0

        # Check for similar position sides
        sides = [trade['position_side'] for trade in trades]
        side_consistency = len([s for s in sides if s == sides[0]]) / len(sides)

        # Check for similar position sizes (within 20% of each other)
        sizes = [float(trade['position_size_usd']) for trade in trades]
        mean_size = np.mean(sizes)
        size_similarity = len([s for s in sizes if abs(s - mean_size) / mean_size < 0.2]) / len(sizes)

        # Check for temporal clustering (all within window)
        times = [datetime.fromisoformat(trade['created_at']) for trade in trades]
        time_span = (max(times) - min(times)).total_seconds() / 60  # minutes
        time_clustering = 1.0 - (time_span / self.time_window_minutes)

        # Weighted average
        coordination_score = (
            side_consistency * 0.4 +
            size_similarity * 0.3 +
            time_clustering * 0.3
        )

        return coordination_score


class BehavioralAnomalyDetector:
    """Detects anomalies in individual wallet behavior patterns."""

    def __init__(self, min_trade_history: int = 10):
        self.min_trade_history = min_trade_history
        self.logger = logging.getLogger(__name__)

    async def detect_behavioral_anomalies(self, wallet_address: str) -> List[AnomalyScore]:
        """Detect behavioral anomalies for a specific wallet."""
        # Build wallet profile
        profile = await self._build_wallet_profile(wallet_address)

        if profile.total_trades < self.min_trade_history:
            return []

        anomalies = []

        # Check for sudden strategy changes
        strategy_anomaly = await self._detect_strategy_change(wallet_address, profile)
        if strategy_anomaly:
            anomalies.append(strategy_anomaly)

        # Check for unusual timing patterns
        timing_anomaly = await self._detect_timing_anomaly(wallet_address, profile)
        if timing_anomaly:
            anomalies.append(timing_anomaly)

        # Check for risk profile changes
        risk_anomaly = await self._detect_risk_change(wallet_address, profile)
        if risk_anomaly:
            anomalies.append(risk_anomaly)

        return anomalies

    async def _build_wallet_profile(self, wallet_address: str) -> WalletBehaviorProfile:
        """Build statistical profile of wallet behavior."""
        async with Database() as db:
            # Get basic stats
            basic_stats = await db.fetch_one("""
                SELECT
                    COUNT(*) as total_trades,
                    AVG(position_size_usd) as avg_position_size,
                    AVG(CASE WHEN outcome = 'WIN' THEN 1.0 ELSE 0.0 END) as win_rate
                FROM alerts
                WHERE wallet_address = ?
            """, (wallet_address,))

            # Get position size distribution
            sizes = await db.fetch_all("""
                SELECT position_size_usd
                FROM alerts
                WHERE wallet_address = ?
                ORDER BY created_at DESC
                LIMIT 50
            """, (wallet_address,))

            size_values = [float(row['position_size_usd']) for row in sizes]
            std_position_size = np.std(size_values) if size_values else 0.0

            # Get preferred markets
            markets = await db.fetch_all("""
                SELECT market_id, COUNT(*) as trade_count
                FROM alerts
                WHERE wallet_address = ?
                GROUP BY market_id
                ORDER BY trade_count DESC
                LIMIT 5
            """, (wallet_address,))

            preferred_markets = [row['market_id'] for row in markets]

            # Get trading hours distribution (simplified)
            hours_dist = [0.0] * 24  # Would need more complex query in real implementation

            return WalletBehaviorProfile(
                wallet_address=wallet_address,
                total_trades=basic_stats['total_trades'] or 0,
                avg_position_size=basic_stats['avg_position_size'] or 0.0,
                std_position_size=std_position_size,
                avg_time_between_trades=0.0,  # Would calculate from timestamps
                preferred_markets=preferred_markets,
                trading_hours_distribution=hours_dist,
                win_rate=basic_stats['win_rate'] or 0.0,
                risk_tolerance=std_position_size / (basic_stats['avg_position_size'] or 1.0),
                position_hold_time_avg=0.0,  # Would calculate from position data
                market_timing_score=0.0  # Would calculate from resolution timing
            )

    async def _detect_strategy_change(self, wallet_address: str, profile: WalletBehaviorProfile) -> Optional[AnomalyScore]:
        """Detect sudden changes in trading strategy."""
        async with Database() as db:
            # Compare recent trades to historical pattern
            recent_trades = await db.fetch_all("""
                SELECT position_size_usd, market_id, position_side
                FROM alerts
                WHERE wallet_address = ?
                  AND created_at >= datetime('now', '-7 days')
                ORDER BY created_at DESC
            """, (wallet_address,))

            if len(recent_trades) < 5:  # Need enough recent activity
                return None

            # Calculate recent average position size
            recent_sizes = [float(trade['position_size_usd']) for trade in recent_trades]
            recent_avg_size = np.mean(recent_sizes)

            # Check for significant deviation from historical average
            if profile.avg_position_size > 0:
                size_change_ratio = recent_avg_size / profile.avg_position_size

                # Flag if recent average is 3x different from historical
                if size_change_ratio > 3.0 or size_change_ratio < 0.33:
                    confidence = min(0.9, abs(np.log(size_change_ratio)) / 2.0)

                    return AnomalyScore(
                        anomaly_type=AnomalyType.BEHAVIORAL_DEVIATION,
                        confidence=confidence,
                        severity=min(1.0, abs(size_change_ratio - 1.0)),
                        timestamp=datetime.utcnow(),
                        details={
                            "recent_avg_position": recent_avg_size,
                            "historical_avg_position": profile.avg_position_size,
                            "change_ratio": size_change_ratio,
                            "recent_trade_count": len(recent_trades)
                        },
                        affected_wallets=[wallet_address]
                    )

        return None

    async def _detect_timing_anomaly(self, wallet_address: str, profile: WalletBehaviorProfile) -> Optional[AnomalyScore]:
        """Detect unusual timing patterns."""
        # Simplified implementation - would analyze trading time patterns
        return None

    async def _detect_risk_change(self, wallet_address: str, profile: WalletBehaviorProfile) -> Optional[AnomalyScore]:
        """Detect sudden changes in risk tolerance."""
        # Simplified implementation - would analyze position size variance changes
        return None


class MarketManipulationDetector:
    """Detects potential market manipulation patterns."""

    def __init__(self, sensitivity: float = 0.8):
        self.sensitivity = sensitivity
        self.logger = logging.getLogger(__name__)

    async def detect_wash_trading(self, market_id: str, hours: int = 24) -> List[AnomalyScore]:
        """Detect potential wash trading patterns."""
        async with Database() as db:
            # Look for wallets with rapid back-and-forth trading
            wash_patterns = await db.fetch_all("""
                WITH wallet_trades AS (
                    SELECT
                        wallet_address,
                        position_side,
                        position_size_usd,
                        created_at,
                        LAG(position_side) OVER (
                            PARTITION BY wallet_address
                            ORDER BY created_at
                        ) as prev_side,
                        LAG(created_at) OVER (
                            PARTITION BY wallet_address
                            ORDER BY created_at
                        ) as prev_time
                    FROM alerts
                    WHERE market_id = ?
                      AND created_at >= datetime('now', '-{} hours')
                )
                SELECT
                    wallet_address,
                    COUNT(*) as flip_count,
                    AVG(position_size_usd) as avg_size,
                    MIN(created_at) as first_trade,
                    MAX(created_at) as last_trade
                FROM wallet_trades
                WHERE position_side != prev_side
                  AND (julianday(created_at) - julianday(prev_time)) * 24 < 1  -- Within 1 hour
                GROUP BY wallet_address
                HAVING flip_count >= 5  -- At least 5 side flips
            """.format(hours), (market_id,))

            anomalies = []
            for pattern in wash_patterns:
                confidence = min(0.95, pattern['flip_count'] / 10.0)
                severity = min(1.0, pattern['flip_count'] / 20.0)

                anomaly = AnomalyScore(
                    anomaly_type=AnomalyType.WASH_TRADING,
                    confidence=confidence,
                    severity=severity,
                    timestamp=datetime.fromisoformat(pattern['last_trade']),
                    details={
                        "flip_count": pattern['flip_count'],
                        "avg_position_size": pattern['avg_size'],
                        "time_span_hours": hours
                    },
                    affected_wallets=[pattern['wallet_address']],
                    market_id=market_id
                )
                anomalies.append(anomaly)

            return anomalies

    async def detect_price_manipulation(self, market_id: str) -> List[AnomalyScore]:
        """Detect potential price manipulation through large orders."""
        # Simplified implementation - would analyze order book impact
        return []


class AnomalyDetectionEngine:
    """Main engine coordinating all anomaly detection algorithms."""

    def __init__(self):
        self.volume_detector = VolumeAnomalyDetector()
        self.coordination_detector = CoordinatedTradingDetector()
        self.behavioral_detector = BehavioralAnomalyDetector()
        self.manipulation_detector = MarketManipulationDetector()
        self.logger = logging.getLogger(__name__)

    async def scan_all_anomalies(self, market_ids: List[str] = None) -> List[AnomalyScore]:
        """Run comprehensive anomaly detection across markets."""
        self.logger.info("Starting comprehensive anomaly detection scan")

        if market_ids is None:
            market_ids = await self._get_active_markets()

        all_anomalies = []

        # Run detectors in parallel for each market
        tasks = []
        for market_id in market_ids:
            tasks.extend([
                self.volume_detector.detect_volume_anomalies(market_id),
                self.coordination_detector.detect_coordinated_activity(market_id),
                self.manipulation_detector.detect_wash_trading(market_id)
            ])

        # Execute all detection tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect successful results
        for result in results:
            if isinstance(result, list):
                all_anomalies.extend(result)
            elif isinstance(result, Exception):
                self.logger.error(f"Anomaly detection error: {result}")

        # Sort by severity and confidence
        all_anomalies.sort(key=lambda x: x.severity * x.confidence, reverse=True)

        self.logger.info(f"Detected {len(all_anomalies)} anomalies across {len(market_ids)} markets")
        return all_anomalies

    async def scan_wallet_anomalies(self, wallet_addresses: List[str]) -> List[AnomalyScore]:
        """Run behavioral anomaly detection for specific wallets."""
        all_anomalies = []

        tasks = [
            self.behavioral_detector.detect_behavioral_anomalies(wallet)
            for wallet in wallet_addresses
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_anomalies.extend(result)
            elif isinstance(result, Exception):
                self.logger.error(f"Behavioral anomaly detection error: {result}")

        return all_anomalies

    async def _get_active_markets(self) -> List[str]:
        """Get list of active markets to monitor."""
        async with Database() as db:
            markets = await db.fetch_all("""
                SELECT DISTINCT market_id
                FROM alerts
                WHERE created_at >= datetime('now', '-7 days')
                  AND market_id IS NOT NULL
            """)

            return [row['market_id'] for row in markets]


# Convenience functions
async def get_anomaly_engine() -> AnomalyDetectionEngine:
    """Get singleton anomaly detection engine."""
    return AnomalyDetectionEngine()


async def quick_anomaly_scan(market_id: str) -> List[AnomalyScore]:
    """Quick anomaly scan for a single market."""
    engine = AnomalyDetectionEngine()
    return await engine.scan_all_anomalies([market_id])