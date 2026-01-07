"""
Performance tracking automation system.

Automatically tracks the effectiveness of alerts, monitors strategy performance,
and provides real-time analytics on detection accuracy and profitability.
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict, deque
import numpy as np
import structlog

from ..secure_logging import get_secure_logger
from ..storage.database import Database
from ..detection.signals import SuspicionReport, SignalType
from ..exceptions import DatabaseError, InsufficientDataError
from ..security_monitoring import SecurityEvent, SecurityEventType, SecurityEventLevel, report_security_event

logger = get_secure_logger(__name__)


@dataclass
class AlertPerformance:
    """Tracks performance of a single alert."""

    alert_id: str
    timestamp: datetime
    wallet_address: str
    market_id: str
    suspicion_score: int
    signals_triggered: List[str]

    # Position details
    position_side: str  # 'YES' or 'NO'
    position_size: float
    entry_price: float

    # Outcome tracking
    market_resolved: bool = False
    resolution_time: Optional[datetime] = None
    market_outcome: Optional[bool] = None  # True if YES won, False if NO won
    actual_pnl: Optional[float] = None

    # Performance metrics
    prediction_correct: Optional[bool] = None
    time_to_resolution: Optional[timedelta] = None
    return_pct: Optional[float] = None

    # Metadata
    followed: bool = False  # Whether we acted on this alert
    notes: str = ""

    def update_outcome(self, market_outcome: bool, resolution_time: datetime):
        """Update alert with market outcome."""
        self.market_resolved = True
        self.market_outcome = market_outcome
        self.resolution_time = resolution_time
        self.time_to_resolution = resolution_time - self.timestamp

        # Calculate if prediction was correct
        if self.position_side == 'YES':
            self.prediction_correct = market_outcome
        else:  # 'NO'
            self.prediction_correct = not market_outcome

        # Calculate P&L if followed
        if self.followed:
            self.actual_pnl = self._calculate_pnl()
            self.return_pct = self.actual_pnl / (self.position_size * self.entry_price)

    def _calculate_pnl(self) -> float:
        """Calculate actual P&L for this alert."""
        if not self.market_resolved or self.market_outcome is None:
            return 0.0

        if self.position_side == 'YES':
            if self.market_outcome:  # YES won
                return self.position_size * (1.0 - self.entry_price)
            else:  # NO won
                return -self.position_size * self.entry_price
        else:  # position_side == 'NO'
            if not self.market_outcome:  # NO won
                return self.position_size * self.entry_price
            else:  # YES won
                return -self.position_size * (1.0 - self.entry_price)


@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics."""

    # Time period
    start_date: datetime
    end_date: datetime
    total_days: int

    # Alert statistics
    total_alerts: int
    alerts_followed: int
    alerts_resolved: int
    follow_rate: float

    # Accuracy metrics
    correct_predictions: int
    incorrect_predictions: int
    accuracy_rate: float
    precision_by_signal: Dict[str, float]

    # Financial performance
    total_pnl: float
    total_return_pct: float
    win_rate: float
    avg_win: float
    avg_loss: float
    profit_factor: float  # gross_profit / gross_loss

    # Risk metrics
    max_drawdown: float
    max_drawdown_pct: float
    sharpe_ratio: float
    calmar_ratio: float
    var_95: float  # Value at Risk 95%

    # Signal effectiveness
    signal_performance: Dict[str, Dict[str, Any]]
    best_performing_signals: List[Tuple[str, float]]
    worst_performing_signals: List[Tuple[str, float]]

    # Temporal analysis
    performance_by_hour: Dict[int, float]  # Hour of day -> avg return
    performance_by_day: Dict[str, float]   # Day of week -> avg return
    performance_trend: List[Tuple[datetime, float]]  # Cumulative performance

    def get_summary(self) -> Dict[str, Any]:
        """Get human-readable summary."""
        return {
            'period': f"{self.start_date.date()} to {self.end_date.date()} ({self.total_days} days)",
            'alerts': {
                'total': self.total_alerts,
                'followed': self.alerts_followed,
                'resolved': self.alerts_resolved,
                'follow_rate': f"{self.follow_rate:.1%}"
            },
            'accuracy': {
                'overall': f"{self.accuracy_rate:.1%}",
                'correct': self.correct_predictions,
                'incorrect': self.incorrect_predictions
            },
            'financial': {
                'total_pnl': f"${self.total_pnl:,.2f}",
                'return': f"{self.total_return_pct:.2%}",
                'win_rate': f"{self.win_rate:.1%}",
                'profit_factor': f"{self.profit_factor:.2f}"
            },
            'risk': {
                'max_drawdown': f"{self.max_drawdown_pct:.2%}",
                'sharpe_ratio': f"{self.sharpe_ratio:.2f}",
                'var_95': f"${self.var_95:,.2f}"
            },
            'top_signals': [
                f"{signal}: {performance:.1%}"
                for signal, performance in self.best_performing_signals[:3]
            ]
        }


class PerformanceTracker:
    """
    Main performance tracking system.

    Automatically monitors alert outcomes, calculates performance metrics,
    and provides real-time feedback on strategy effectiveness.
    """

    def __init__(self, database: Database):
        self.database = database
        self.alerts: Dict[str, AlertPerformance] = {}
        self.performance_cache: Dict[str, PerformanceMetrics] = {}

        # Real-time tracking
        self.recent_alerts: deque = deque(maxlen=1000)
        self.performance_buffer: List[float] = []

        # Configuration
        self.auto_update_enabled = True
        self.performance_update_interval = 3600  # Update every hour

        logger.info("performance_tracker_initialized")

    async def track_alert(self, alert: SuspicionReport, followed: bool = False) -> str:
        """
        Start tracking a new alert.

        Args:
            alert: SuspicionReport to track
            followed: Whether we acted on this alert

        Returns:
            Alert tracking ID
        """
        try:
            alert_id = f"alert_{int(alert.timestamp.timestamp())}"

            # Create performance tracking record
            performance = AlertPerformance(
                alert_id=alert_id,
                timestamp=alert.timestamp,
                wallet_address=alert.wallet_profile.address,
                market_id=alert.market_context.get('market_id', ''),
                suspicion_score=alert.total_score,
                signals_triggered=[signal.value for signal in alert.triggered_signals],
                position_side=alert.market_context.get('position_side', 'YES'),
                position_size=alert.market_context.get('position_size_usd', 0.0),
                entry_price=alert.market_context.get('current_price', 0.5),
                followed=followed
            )

            # Store in memory and database
            self.alerts[alert_id] = performance
            self.recent_alerts.append(performance)

            await self._save_alert_performance(performance)

            logger.info("alert_tracking_started",
                       alert_id=alert_id,
                       wallet=alert.wallet_profile.address[:10],
                       market=alert.market_context.get('market_id', '')[:10],
                       suspicion_score=alert.total_score,
                       followed=followed)

            return alert_id

        except Exception as e:
            logger.error("alert_tracking_failed", error=str(e))
            raise DatabaseError(f"Failed to track alert: {e}")

    async def update_alert_outcome(self,
                                 alert_id: str,
                                 market_outcome: bool,
                                 resolution_time: Optional[datetime] = None) -> None:
        """
        Update an alert with its market outcome.

        Args:
            alert_id: Alert tracking ID
            market_outcome: True if YES won, False if NO won
            resolution_time: When the market resolved
        """
        try:
            if alert_id not in self.alerts:
                logger.warning("alert_not_found_for_update", alert_id=alert_id)
                return

            alert = self.alerts[alert_id]
            resolution_time = resolution_time or datetime.now(timezone.utc)

            # Update outcome
            alert.update_outcome(market_outcome, resolution_time)

            # Save to database
            await self._update_alert_performance(alert)

            # Update real-time metrics
            if alert.followed and alert.actual_pnl is not None:
                self.performance_buffer.append(alert.actual_pnl)

            logger.info("alert_outcome_updated",
                       alert_id=alert_id,
                       market_outcome=market_outcome,
                       prediction_correct=alert.prediction_correct,
                       pnl=alert.actual_pnl)

            # Check for performance alerts
            await self._check_performance_alerts(alert)

        except Exception as e:
            logger.error("alert_outcome_update_failed",
                        alert_id=alert_id,
                        error=str(e))

    async def _check_performance_alerts(self, alert: AlertPerformance):
        """Check if alert performance triggers any system alerts."""
        try:
            # Large loss alert
            if alert.followed and alert.actual_pnl and alert.actual_pnl < -1000:
                await report_security_event(
                    SecurityEventType.SYSTEM_ANOMALY,
                    SecurityEventLevel.HIGH,
                    "Large trading loss detected",
                    f"Alert {alert.alert_id} resulted in ${alert.actual_pnl:,.2f} loss",
                    "performance_tracker",
                    metadata={
                        'alert_id': alert.alert_id,
                        'pnl': alert.actual_pnl,
                        'market_id': alert.market_id
                    }
                )

            # High-confidence incorrect prediction
            if (alert.suspicion_score > 80 and
                alert.prediction_correct is False):
                await report_security_event(
                    SecurityEventType.SYSTEM_ANOMALY,
                    SecurityEventLevel.MEDIUM,
                    "High-confidence prediction failed",
                    f"Alert with {alert.suspicion_score}% confidence was incorrect",
                    "performance_tracker",
                    metadata={
                        'alert_id': alert.alert_id,
                        'suspicion_score': alert.suspicion_score,
                        'signals': alert.signals_triggered
                    }
                )

        except Exception as e:
            logger.warning("performance_alert_check_failed", error=str(e))

    async def calculate_metrics(self,
                              start_date: Optional[datetime] = None,
                              end_date: Optional[datetime] = None) -> PerformanceMetrics:
        """
        Calculate comprehensive performance metrics.

        Args:
            start_date: Start of analysis period
            end_date: End of analysis period

        Returns:
            PerformanceMetrics object
        """
        try:
            # Default to last 30 days if not specified
            if not end_date:
                end_date = datetime.now(timezone.utc)
            if not start_date:
                start_date = end_date - timedelta(days=30)

            # Get relevant alerts
            relevant_alerts = [
                alert for alert in self.alerts.values()
                if start_date <= alert.timestamp <= end_date
            ]

            if not relevant_alerts:
                raise InsufficientDataError(
                    "alert_data",
                    f"No alerts found in period {start_date.date()} to {end_date.date()}"
                )

            logger.info("calculating_performance_metrics",
                       start_date=start_date.date(),
                       end_date=end_date.date(),
                       total_alerts=len(relevant_alerts))

            # Calculate all metrics
            metrics = await self._compute_metrics(relevant_alerts, start_date, end_date)

            # Cache results
            cache_key = f"{start_date.date()}_{end_date.date()}"
            self.performance_cache[cache_key] = metrics

            return metrics

        except Exception as e:
            logger.error("performance_calculation_failed", error=str(e))
            raise

    async def _compute_metrics(self,
                             alerts: List[AlertPerformance],
                             start_date: datetime,
                             end_date: datetime) -> PerformanceMetrics:
        """Compute all performance metrics from alert data."""
        total_days = (end_date - start_date).days

        # Basic alert statistics
        total_alerts = len(alerts)
        followed_alerts = [a for a in alerts if a.followed]
        resolved_alerts = [a for a in alerts if a.market_resolved]
        alerts_followed = len(followed_alerts)
        alerts_resolved = len(resolved_alerts)
        follow_rate = alerts_followed / max(total_alerts, 1)

        # Accuracy metrics
        resolved_followed = [a for a in followed_alerts if a.market_resolved]
        correct_predictions = sum(1 for a in resolved_followed if a.prediction_correct)
        incorrect_predictions = len(resolved_followed) - correct_predictions
        accuracy_rate = correct_predictions / max(len(resolved_followed), 1)

        # Financial metrics
        pnls = [a.actual_pnl for a in followed_alerts if a.actual_pnl is not None]
        total_pnl = sum(pnls)

        winning_trades = [pnl for pnl in pnls if pnl > 0]
        losing_trades = [pnl for pnl in pnls if pnl < 0]

        win_rate = len(winning_trades) / max(len(pnls), 1)
        avg_win = np.mean(winning_trades) if winning_trades else 0.0
        avg_loss = np.mean(losing_trades) if losing_trades else 0.0

        gross_profit = sum(winning_trades)
        gross_loss = abs(sum(losing_trades))
        profit_factor = gross_profit / max(gross_loss, 1)

        # Risk metrics
        if pnls:
            cumulative_pnl = np.cumsum(pnls)
            peak = np.maximum.accumulate(cumulative_pnl)
            drawdown = peak - cumulative_pnl
            max_drawdown = np.max(drawdown)

            total_capital = 10000.0  # Assume $10k starting capital
            total_return_pct = total_pnl / total_capital
            max_drawdown_pct = max_drawdown / total_capital

            # Sharpe ratio (simplified)
            if len(pnls) > 1:
                returns = np.array(pnls) / total_capital
                sharpe_ratio = np.mean(returns) / np.std(returns) * np.sqrt(252) if np.std(returns) > 0 else 0
            else:
                sharpe_ratio = 0.0

            calmar_ratio = total_return_pct / max(max_drawdown_pct, 0.01)
            var_95 = np.percentile(pnls, 5) if len(pnls) >= 20 else 0.0
        else:
            total_return_pct = 0.0
            max_drawdown = 0.0
            max_drawdown_pct = 0.0
            sharpe_ratio = 0.0
            calmar_ratio = 0.0
            var_95 = 0.0

        # Signal analysis
        signal_performance = self._analyze_signal_performance(resolved_followed)
        precision_by_signal = {
            signal: data['precision'] for signal, data in signal_performance.items()
        }

        best_signals = sorted(
            [(s, d['avg_return']) for s, d in signal_performance.items()],
            key=lambda x: x[1], reverse=True
        )[:5]

        worst_signals = sorted(
            [(s, d['avg_return']) for s, d in signal_performance.items()],
            key=lambda x: x[1]
        )[:5]

        # Temporal analysis
        performance_by_hour = self._analyze_hourly_performance(followed_alerts)
        performance_by_day = self._analyze_daily_performance(followed_alerts)
        performance_trend = self._calculate_performance_trend(followed_alerts)

        return PerformanceMetrics(
            start_date=start_date,
            end_date=end_date,
            total_days=total_days,
            total_alerts=total_alerts,
            alerts_followed=alerts_followed,
            alerts_resolved=alerts_resolved,
            follow_rate=follow_rate,
            correct_predictions=correct_predictions,
            incorrect_predictions=incorrect_predictions,
            accuracy_rate=accuracy_rate,
            precision_by_signal=precision_by_signal,
            total_pnl=total_pnl,
            total_return_pct=total_return_pct,
            win_rate=win_rate,
            avg_win=avg_win,
            avg_loss=avg_loss,
            profit_factor=profit_factor,
            max_drawdown=max_drawdown,
            max_drawdown_pct=max_drawdown_pct,
            sharpe_ratio=sharpe_ratio,
            calmar_ratio=calmar_ratio,
            var_95=var_95,
            signal_performance=signal_performance,
            best_performing_signals=best_signals,
            worst_performing_signals=worst_signals,
            performance_by_hour=performance_by_hour,
            performance_by_day=performance_by_day,
            performance_trend=performance_trend
        )

    def _analyze_signal_performance(self, alerts: List[AlertPerformance]) -> Dict[str, Dict[str, Any]]:
        """Analyze performance by signal type."""
        signal_stats = defaultdict(lambda: {
            'count': 0,
            'correct': 0,
            'total_pnl': 0.0,
            'pnls': []
        })

        for alert in alerts:
            for signal in alert.signals_triggered:
                stats = signal_stats[signal]
                stats['count'] += 1

                if alert.prediction_correct:
                    stats['correct'] += 1

                if alert.actual_pnl is not None:
                    stats['total_pnl'] += alert.actual_pnl
                    stats['pnls'].append(alert.actual_pnl)

        # Calculate derived metrics
        performance = {}
        for signal, stats in signal_stats.items():
            performance[signal] = {
                'count': stats['count'],
                'precision': stats['correct'] / max(stats['count'], 1),
                'total_pnl': stats['total_pnl'],
                'avg_return': np.mean(stats['pnls']) if stats['pnls'] else 0.0,
                'win_rate': len([p for p in stats['pnls'] if p > 0]) / max(len(stats['pnls']), 1)
            }

        return performance

    def _analyze_hourly_performance(self, alerts: List[AlertPerformance]) -> Dict[int, float]:
        """Analyze performance by hour of day."""
        hourly_pnl = defaultdict(list)

        for alert in alerts:
            if alert.actual_pnl is not None:
                hour = alert.timestamp.hour
                hourly_pnl[hour].append(alert.actual_pnl)

        return {
            hour: np.mean(pnls) if pnls else 0.0
            for hour, pnls in hourly_pnl.items()
        }

    def _analyze_daily_performance(self, alerts: List[AlertPerformance]) -> Dict[str, float]:
        """Analyze performance by day of week."""
        daily_pnl = defaultdict(list)
        day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

        for alert in alerts:
            if alert.actual_pnl is not None:
                day_name = day_names[alert.timestamp.weekday()]
                daily_pnl[day_name].append(alert.actual_pnl)

        return {
            day: np.mean(pnls) if pnls else 0.0
            for day, pnls in daily_pnl.items()
        }

    def _calculate_performance_trend(self, alerts: List[AlertPerformance]) -> List[Tuple[datetime, float]]:
        """Calculate cumulative performance trend over time."""
        # Sort alerts by time
        sorted_alerts = sorted(
            [a for a in alerts if a.actual_pnl is not None],
            key=lambda x: x.timestamp
        )

        cumulative_pnl = 0.0
        trend = []

        for alert in sorted_alerts:
            cumulative_pnl += alert.actual_pnl
            trend.append((alert.timestamp, cumulative_pnl))

        return trend

    async def _save_alert_performance(self, performance: AlertPerformance):
        """Save alert performance to database."""
        # Implementation would save to database
        # For now, just log
        logger.debug("alert_performance_saved", alert_id=performance.alert_id)

    async def _update_alert_performance(self, performance: AlertPerformance):
        """Update alert performance in database."""
        # Implementation would update database record
        # For now, just log
        logger.debug("alert_performance_updated", alert_id=performance.alert_id)

    async def generate_performance_report(self,
                                        days_back: int = 30) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days_back)

        try:
            metrics = await self.calculate_metrics(start_date, end_date)

            report = {
                'report_generated': datetime.now(timezone.utc).isoformat(),
                'summary': metrics.get_summary(),
                'detailed_metrics': {
                    'temporal_analysis': {
                        'hourly_performance': metrics.performance_by_hour,
                        'daily_performance': metrics.performance_by_day
                    },
                    'signal_analysis': metrics.signal_performance,
                    'risk_metrics': {
                        'var_95': metrics.var_95,
                        'max_drawdown': metrics.max_drawdown_pct,
                        'sharpe_ratio': metrics.sharpe_ratio
                    }
                },
                'recommendations': self._generate_recommendations(metrics)
            }

            logger.info("performance_report_generated",
                       period_days=days_back,
                       total_alerts=metrics.total_alerts,
                       accuracy_rate=metrics.accuracy_rate,
                       total_return=metrics.total_return_pct)

            return report

        except Exception as e:
            logger.error("performance_report_failed", error=str(e))
            raise

    def _generate_recommendations(self, metrics: PerformanceMetrics) -> List[str]:
        """Generate actionable recommendations based on performance."""
        recommendations = []

        # Accuracy recommendations
        if metrics.accuracy_rate < 0.6:
            recommendations.append(
                f"Accuracy rate is {metrics.accuracy_rate:.1%}. Consider increasing alert threshold or reviewing signal weights."
            )

        # Signal recommendations
        if metrics.best_performing_signals and metrics.worst_performing_signals:
            best_signal = metrics.best_performing_signals[0]
            worst_signal = metrics.worst_performing_signals[0]

            recommendations.append(
                f"Best performing signal: {best_signal[0]} ({best_signal[1]:.2%} avg return). "
                f"Consider increasing its weight."
            )

            if worst_signal[1] < -0.05:  # Less than -5% return
                recommendations.append(
                    f"Worst performing signal: {worst_signal[0]} ({worst_signal[1]:.2%} avg return). "
                    f"Consider reducing its weight or reviewing logic."
                )

        # Risk recommendations
        if metrics.max_drawdown_pct > 0.2:
            recommendations.append(
                f"High maximum drawdown of {metrics.max_drawdown_pct:.2%}. "
                f"Consider implementing stricter risk management."
            )

        # Volume recommendations
        if metrics.follow_rate < 0.1:
            recommendations.append(
                f"Low follow rate of {metrics.follow_rate:.1%}. "
                f"Consider lowering alert threshold to capture more opportunities."
            )

        return recommendations


async def test_performance_tracker():
    """Test performance tracking functionality."""
    print("📈 Testing Performance Tracker")
    print("=" * 35)

    try:
        # Mock database
        database = None  # Would be Database() in real implementation

        tracker = PerformanceTracker(database)

        # Create sample alert data
        from ..detection.signals import WalletProfile, SuspicionReport, SignalType

        wallet = WalletProfile(
            address="0x1111111111111111111111111111111111111111",
            first_seen=datetime.now(timezone.utc) - timedelta(days=5),
            total_trades=10,
            total_volume_usd=5000.0,
            winning_trades=0,
            is_fresh=True
        )

        # Sample alerts
        sample_alerts = []
        for i in range(5):
            alert = SuspicionReport(
                wallet_profile=wallet,
                triggered_signals=[SignalType.FRESH_WALLET],
                signal_breakdown={'fresh_wallet': 25},
                total_score=70 + i * 5,
                market_context={
                    'market_id': f'market_{i}',
                    'position_side': 'YES',
                    'position_size_usd': 1000.0,
                    'current_price': 0.6
                },
                timestamp=datetime.now(timezone.utc) - timedelta(hours=i),
                metadata={}
            )
            sample_alerts.append(alert)

        # Track alerts
        alert_ids = []
        for i, alert in enumerate(sample_alerts):
            alert_id = await tracker.track_alert(alert, followed=True)
            alert_ids.append(alert_id)

            # Simulate outcomes
            market_outcome = i % 2 == 0  # Alternate wins/losses
            await tracker.update_alert_outcome(
                alert_id,
                market_outcome,
                datetime.now(timezone.utc)
            )

        # Generate performance report
        report = await tracker.generate_performance_report(days_back=7)

        print("✅ Performance tracking test completed!")
        print(f"  Tracked alerts: {len(alert_ids)}")
        print(f"  Accuracy rate: {report['summary']['accuracy']['overall']}")
        print(f"  Win rate: {report['summary']['financial']['win_rate']}")

        print("\n📊 Recommendations:")
        for rec in report['recommendations']:
            print(f"  • {rec}")

    except Exception as e:
        print(f"❌ Test failed: {e}")


# Convenience function for singleton pattern
async def get_performance_tracker() -> PerformanceTracker:
    """Get singleton performance tracker."""
    from ..storage.database import Database
    db = Database()
    return PerformanceTracker(db)


if __name__ == "__main__":
    asyncio.run(test_performance_tracker())