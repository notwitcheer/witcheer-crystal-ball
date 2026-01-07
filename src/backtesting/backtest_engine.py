"""
Historical backtesting engine for strategy validation.

Tests detection algorithms against historical data to evaluate performance,
optimize parameters, and validate strategy effectiveness before live trading.
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict
import numpy as np
import structlog

from ..secure_logging import get_secure_logger
from ..detection import InsiderDetector, WalletProfile, SuspicionReport, SignalType
from ..storage.database import Database
from ..exceptions import InsufficientDataError, DetectionError

logger = get_secure_logger(__name__)


@dataclass
class BacktestTrade:
    """Represents a historical trade for backtesting."""

    timestamp: datetime
    wallet_address: str
    market_id: str
    side: str  # 'YES' or 'NO'
    size: float
    price: float
    outcome: Optional[bool] = None  # True if won, False if lost, None if unresolved
    market_resolution_time: Optional[datetime] = None
    pnl: Optional[float] = None

    def calculate_pnl(self) -> float:
        """Calculate P&L for this trade."""
        if self.outcome is None:
            return 0.0

        if self.side == 'YES':
            return self.size * (1.0 - self.price) if self.outcome else -self.size * self.price
        else:  # 'NO'
            return self.size * self.price if not self.outcome else -self.size * (1.0 - self.price)


@dataclass
class BacktestAlert:
    """Represents an alert generated during backtesting."""

    timestamp: datetime
    alert_id: str
    wallet_address: str
    market_id: str
    suspicion_score: int
    signals_triggered: List[str]
    position_size: float
    position_side: str
    price_at_detection: float

    # Backtesting specific
    followed: bool = False  # Whether we "followed" this alert
    outcome: Optional[bool] = None  # Market outcome
    pnl: Optional[float] = None  # P&L if followed
    time_to_resolution: Optional[timedelta] = None


@dataclass
class BacktestConfig:
    """Configuration for backtesting parameters."""

    # Time period
    start_date: datetime
    end_date: datetime

    # Strategy parameters
    follow_threshold: int = 70  # Minimum suspicion score to follow
    max_position_size: float = 1000.0  # Maximum position size per trade
    position_sizing_method: str = "fixed"  # "fixed", "proportional", "kelly"

    # Risk management
    stop_loss_pct: float = 0.5  # Stop loss at 50% position loss
    take_profit_pct: float = 0.9  # Take profit at 90% position gain
    max_concurrent_positions: int = 10  # Maximum simultaneous positions

    # Detection tuning
    detection_params: Dict[str, Any] = field(default_factory=dict)

    # Performance calculation
    initial_capital: float = 10000.0
    transaction_cost_pct: float = 0.01  # 1% transaction cost


@dataclass
class BacktestResults:
    """Results of a backtesting run."""

    # Configuration
    config: BacktestConfig
    total_duration: timedelta

    # Alert statistics
    total_alerts: int
    alerts_followed: int
    follow_rate: float

    # Performance metrics
    total_trades: int
    winning_trades: int
    losing_trades: int
    win_rate: float

    # Financial metrics
    initial_capital: float
    final_capital: float
    total_return: float
    total_return_pct: float
    max_drawdown: float
    max_drawdown_pct: float
    sharpe_ratio: float
    calmar_ratio: float

    # Strategy specific
    avg_hold_time: timedelta
    avg_position_size: float
    best_trade: float
    worst_trade: float

    # Detailed results
    trades: List[BacktestAlert] = field(default_factory=list)
    equity_curve: List[Tuple[datetime, float]] = field(default_factory=list)
    drawdown_curve: List[Tuple[datetime, float]] = field(default_factory=list)

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get human-readable performance summary."""
        return {
            'period': f"{self.config.start_date.date()} to {self.config.end_date.date()}",
            'duration_days': self.total_duration.days,
            'alerts': {
                'total': self.total_alerts,
                'followed': self.alerts_followed,
                'follow_rate': f"{self.follow_rate:.1%}"
            },
            'trades': {
                'total': self.total_trades,
                'winning': self.winning_trades,
                'losing': self.losing_trades,
                'win_rate': f"{self.win_rate:.1%}"
            },
            'returns': {
                'total_return': f"{self.total_return_pct:.2%}",
                'sharpe_ratio': f"{self.sharpe_ratio:.2f}",
                'max_drawdown': f"{self.max_drawdown_pct:.2%}"
            },
            'capital': {
                'initial': f"${self.initial_capital:,.2f}",
                'final': f"${self.final_capital:,.2f}",
                'profit': f"${self.total_return:,.2f}"
            }
        }


class HistoricalDataManager:
    """Manages historical trade and market data for backtesting."""

    def __init__(self, database: Database):
        self.database = database
        self.data_cache: Dict[str, Any] = {}

    async def load_historical_trades(self,
                                   start_date: datetime,
                                   end_date: datetime,
                                   min_volume: float = 1000.0) -> List[BacktestTrade]:
        """
        Load historical trades for the specified time period.

        Args:
            start_date: Start of backtesting period
            end_date: End of backtesting period
            min_volume: Minimum market volume to include

        Returns:
            List of BacktestTrade objects
        """
        cache_key = f"trades_{start_date}_{end_date}_{min_volume}"

        if cache_key in self.data_cache:
            return self.data_cache[cache_key]

        try:
            # This would typically load from database or external API
            # For now, we'll create sample data
            trades = await self._generate_sample_historical_data(start_date, end_date)

            self.data_cache[cache_key] = trades

            logger.info("historical_trades_loaded",
                       count=len(trades),
                       start_date=start_date.date(),
                       end_date=end_date.date())

            return trades

        except Exception as e:
            logger.error("historical_data_load_failed",
                        start_date=start_date.date(),
                        end_date=end_date.date(),
                        error=str(e))
            raise InsufficientDataError(
                "historical_trades",
                f"Failed to load historical data: {e}"
            )

    async def _generate_sample_historical_data(self,
                                             start_date: datetime,
                                             end_date: datetime) -> List[BacktestTrade]:
        """Generate sample historical data for testing."""
        trades = []
        current_date = start_date

        # Sample wallets
        wallets = [
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
            "0x3333333333333333333333333333333333333333",
            "0x4444444444444444444444444444444444444444"
        ]

        # Sample markets
        markets = ["market_1", "market_2", "market_3", "market_4", "market_5"]

        while current_date < end_date:
            # Generate random trades for this day
            num_trades = np.random.randint(5, 20)

            for _ in range(num_trades):
                trade = BacktestTrade(
                    timestamp=current_date + timedelta(
                        hours=np.random.randint(0, 24),
                        minutes=np.random.randint(0, 60)
                    ),
                    wallet_address=np.random.choice(wallets),
                    market_id=np.random.choice(markets),
                    side=np.random.choice(['YES', 'NO']),
                    size=np.random.uniform(100, 2000),
                    price=np.random.uniform(0.1, 0.9),
                    outcome=np.random.choice([True, False]) if np.random.random() > 0.3 else None,
                    market_resolution_time=current_date + timedelta(days=np.random.randint(1, 7))
                )

                # Calculate P&L
                trade.pnl = trade.calculate_pnl()
                trades.append(trade)

            current_date += timedelta(days=1)

        return sorted(trades, key=lambda x: x.timestamp)

    async def get_market_outcomes(self, market_ids: Set[str]) -> Dict[str, bool]:
        """Get outcomes for specified markets."""
        # In a real implementation, this would query historical market resolution data
        outcomes = {}
        for market_id in market_ids:
            # Random outcome for testing
            outcomes[market_id] = np.random.choice([True, False])

        return outcomes


class BacktestEngine:
    """
    Main backtesting engine that simulates strategy performance.
    """

    def __init__(self, database: Database):
        self.database = database
        self.data_manager = HistoricalDataManager(database)
        self.detection_engine = InsiderDetector()

    async def run_backtest(self, config: BacktestConfig) -> BacktestResults:
        """
        Run a complete backtest simulation.

        Args:
            config: Backtesting configuration

        Returns:
            BacktestResults with performance metrics
        """
        logger.info("backtest_starting",
                   start_date=config.start_date.date(),
                   end_date=config.end_date.date(),
                   follow_threshold=config.follow_threshold)

        try:
            # Load historical data
            trades = await self.data_manager.load_historical_trades(
                config.start_date,
                config.end_date
            )

            if not trades:
                raise InsufficientDataError(
                    "historical_trades",
                    "No historical trades available for backtesting period"
                )

            # Run simulation
            alerts = await self._simulate_detection(trades, config)
            results = await self._calculate_performance(alerts, config)

            logger.info("backtest_completed",
                       duration_days=results.total_duration.days,
                       total_alerts=results.total_alerts,
                       win_rate=results.win_rate,
                       total_return_pct=results.total_return_pct)

            return results

        except Exception as e:
            logger.error("backtest_failed", error=str(e))
            raise DetectionError("backtesting", f"Backtest failed: {e}")

    async def _simulate_detection(self,
                                trades: List[BacktestTrade],
                                config: BacktestConfig) -> List[BacktestAlert]:
        """Simulate running detection algorithms on historical data."""
        alerts = []
        wallet_histories: Dict[str, List[Dict]] = defaultdict(list)

        logger.info("simulating_detection",
                   total_trades=len(trades),
                   detection_threshold=config.follow_threshold)

        for trade in trades:
            # Add trade to wallet history
            trade_dict = {
                'timestamp': trade.timestamp.isoformat(),
                'market': trade.market_id,
                'side': trade.side,
                'size': trade.size,
                'price': trade.price
            }
            wallet_histories[trade.wallet_address].append(trade_dict)

            # Run detection if wallet has sufficient history
            if len(wallet_histories[trade.wallet_address]) >= 3:
                try:
                    # Create wallet profile
                    wallet_trades = wallet_histories[trade.wallet_address]
                    wallet_profile = WalletProfile(
                        address=trade.wallet_address,
                        first_seen=datetime.fromisoformat(wallet_trades[0]['timestamp']),
                        total_trades=len(wallet_trades),
                        total_volume_usd=sum(float(t['size']) for t in wallet_trades),
                        winning_trades=0,  # Would need outcome data
                        is_fresh=len(wallet_trades) <= 5
                    )

                    # Run detection (simplified)
                    suspicion_score = await self._calculate_suspicion_score(
                        wallet_profile, trade, wallet_trades
                    )

                    if suspicion_score >= 50:  # Generate alert
                        alert = BacktestAlert(
                            timestamp=trade.timestamp,
                            alert_id=f"alert_{len(alerts)+1}",
                            wallet_address=trade.wallet_address,
                            market_id=trade.market_id,
                            suspicion_score=suspicion_score,
                            signals_triggered=self._get_triggered_signals(wallet_profile, trade),
                            position_size=trade.size,
                            position_side=trade.side,
                            price_at_detection=trade.price
                        )

                        # Determine if we would follow this alert
                        alert.followed = suspicion_score >= config.follow_threshold

                        # Set outcome and calculate P&L
                        alert.outcome = trade.outcome
                        if alert.followed and trade.outcome is not None:
                            alert.pnl = self._calculate_alert_pnl(alert, trade)
                            alert.time_to_resolution = (
                                trade.market_resolution_time - trade.timestamp
                                if trade.market_resolution_time else timedelta(days=1)
                            )

                        alerts.append(alert)

                except Exception as e:
                    logger.warning("detection_simulation_error",
                                 wallet=trade.wallet_address[:10],
                                 error=str(e))

        logger.info("detection_simulation_completed",
                   total_alerts=len(alerts),
                   followed_alerts=sum(1 for a in alerts if a.followed))

        return alerts

    async def _calculate_suspicion_score(self,
                                       wallet_profile: WalletProfile,
                                       trade: BacktestTrade,
                                       trade_history: List[Dict]) -> int:
        """Calculate simplified suspicion score for backtesting."""
        score = 0

        # Fresh wallet signal
        if wallet_profile.is_fresh and trade.size > 500:
            score += 25

        # Unusual sizing signal
        avg_size = np.mean([float(t['size']) for t in trade_history])
        if trade.size > avg_size * 2:
            score += 20

        # Random component for testing
        score += np.random.randint(0, 30)

        return min(100, score)

    def _get_triggered_signals(self, wallet_profile: WalletProfile, trade: BacktestTrade) -> List[str]:
        """Get list of triggered signals for simplified detection."""
        signals = []

        if wallet_profile.is_fresh:
            signals.append("fresh_wallet")

        if trade.size > 1000:
            signals.append("unusual_sizing")

        return signals

    def _calculate_alert_pnl(self, alert: BacktestAlert, trade: BacktestTrade) -> float:
        """Calculate P&L for following an alert."""
        if trade.outcome is None:
            return 0.0

        # Simplified P&L calculation
        position_size = min(alert.position_size, 1000.0)  # Cap position size

        if alert.position_side == 'YES':
            return position_size * (1.0 - alert.price_at_detection) if trade.outcome else -position_size * alert.price_at_detection
        else:  # 'NO'
            return position_size * alert.price_at_detection if not trade.outcome else -position_size * (1.0 - alert.price_at_detection)

    async def _calculate_performance(self,
                                   alerts: List[BacktestAlert],
                                   config: BacktestConfig) -> BacktestResults:
        """Calculate performance metrics from backtesting results."""
        followed_alerts = [a for a in alerts if a.followed]

        # Basic statistics
        total_alerts = len(alerts)
        alerts_followed = len(followed_alerts)
        follow_rate = alerts_followed / max(total_alerts, 1)

        # Trade statistics
        resolved_trades = [a for a in followed_alerts if a.outcome is not None]
        total_trades = len(resolved_trades)
        winning_trades = sum(1 for a in resolved_trades if a.pnl and a.pnl > 0)
        losing_trades = total_trades - winning_trades
        win_rate = winning_trades / max(total_trades, 1)

        # Financial metrics
        total_pnl = sum(a.pnl for a in resolved_trades if a.pnl is not None)
        initial_capital = config.initial_capital
        final_capital = initial_capital + total_pnl
        total_return = total_pnl
        total_return_pct = total_return / initial_capital

        # Calculate equity curve and drawdown
        equity_curve = self._calculate_equity_curve(resolved_trades, initial_capital)
        max_drawdown, max_drawdown_pct = self._calculate_max_drawdown(equity_curve)

        # Risk metrics
        returns = [a.pnl / initial_capital for a in resolved_trades if a.pnl is not None]
        sharpe_ratio = self._calculate_sharpe_ratio(returns) if returns else 0.0

        # Hold time analysis
        hold_times = [a.time_to_resolution for a in resolved_trades if a.time_to_resolution]
        avg_hold_time = (
            sum(hold_times, timedelta()) / len(hold_times)
            if hold_times else timedelta()
        )

        # Position size analysis
        position_sizes = [a.position_size for a in followed_alerts if a.position_size]
        avg_position_size = np.mean(position_sizes) if position_sizes else 0.0

        # Best and worst trades
        pnls = [a.pnl for a in resolved_trades if a.pnl is not None]
        best_trade = max(pnls) if pnls else 0.0
        worst_trade = min(pnls) if pnls else 0.0

        results = BacktestResults(
            config=config,
            total_duration=config.end_date - config.start_date,
            total_alerts=total_alerts,
            alerts_followed=alerts_followed,
            follow_rate=follow_rate,
            total_trades=total_trades,
            winning_trades=winning_trades,
            losing_trades=losing_trades,
            win_rate=win_rate,
            initial_capital=initial_capital,
            final_capital=final_capital,
            total_return=total_return,
            total_return_pct=total_return_pct,
            max_drawdown=max_drawdown,
            max_drawdown_pct=max_drawdown_pct,
            sharpe_ratio=sharpe_ratio,
            calmar_ratio=total_return_pct / max(abs(max_drawdown_pct), 0.01),
            avg_hold_time=avg_hold_time,
            avg_position_size=avg_position_size,
            best_trade=best_trade,
            worst_trade=worst_trade,
            trades=followed_alerts,
            equity_curve=equity_curve
        )

        return results

    def _calculate_equity_curve(self,
                              trades: List[BacktestAlert],
                              initial_capital: float) -> List[Tuple[datetime, float]]:
        """Calculate equity curve over time."""
        equity_curve = [(trades[0].timestamp if trades else datetime.now(), initial_capital)]
        current_capital = initial_capital

        for trade in trades:
            if trade.pnl is not None:
                current_capital += trade.pnl
                equity_curve.append((trade.timestamp, current_capital))

        return equity_curve

    def _calculate_max_drawdown(self, equity_curve: List[Tuple[datetime, float]]) -> Tuple[float, float]:
        """Calculate maximum drawdown from equity curve."""
        if len(equity_curve) < 2:
            return 0.0, 0.0

        max_equity = equity_curve[0][1]
        max_drawdown = 0.0

        for timestamp, equity in equity_curve:
            if equity > max_equity:
                max_equity = equity

            drawdown = max_equity - equity
            if drawdown > max_drawdown:
                max_drawdown = drawdown

        max_drawdown_pct = max_drawdown / max_equity if max_equity > 0 else 0.0
        return max_drawdown, max_drawdown_pct

    def _calculate_sharpe_ratio(self, returns: List[float], risk_free_rate: float = 0.02) -> float:
        """Calculate Sharpe ratio."""
        if not returns:
            return 0.0

        mean_return = np.mean(returns)
        std_return = np.std(returns)

        if std_return == 0:
            return 0.0

        # Annualized Sharpe ratio
        sharpe = (mean_return * 252 - risk_free_rate) / (std_return * np.sqrt(252))
        return sharpe


class ParameterOptimizer:
    """Optimizes detection parameters using historical backtesting."""

    def __init__(self, backtest_engine: BacktestEngine):
        self.backtest_engine = backtest_engine

    async def optimize_parameters(self,
                                config: BacktestConfig,
                                parameters_to_optimize: Dict[str, List[Any]],
                                optimization_metric: str = "sharpe_ratio") -> Dict[str, Any]:
        """
        Optimize detection parameters using grid search.

        Args:
            config: Base backtesting configuration
            parameters_to_optimize: Dict of parameter_name -> [values_to_test]
            optimization_metric: Metric to optimize

        Returns:
            Best parameter combination
        """
        logger.info("parameter_optimization_starting",
                   parameters=list(parameters_to_optimize.keys()),
                   combinations=np.prod([len(v) for v in parameters_to_optimize.values()]))

        best_params = {}
        best_metric = float('-inf')
        results_history = []

        # Generate all parameter combinations
        from itertools import product

        param_names = list(parameters_to_optimize.keys())
        param_values = list(parameters_to_optimize.values())

        for combination in product(*param_values):
            # Create config for this combination
            test_config = config
            param_dict = dict(zip(param_names, combination))

            # Update config with test parameters
            if 'follow_threshold' in param_dict:
                test_config.follow_threshold = param_dict['follow_threshold']
            if 'max_position_size' in param_dict:
                test_config.max_position_size = param_dict['max_position_size']

            try:
                # Run backtest
                results = await self.backtest_engine.run_backtest(test_config)

                # Get metric value
                metric_value = getattr(results, optimization_metric, 0.0)

                results_history.append({
                    'parameters': param_dict,
                    'metric_value': metric_value,
                    'total_return': results.total_return_pct,
                    'win_rate': results.win_rate,
                    'sharpe_ratio': results.sharpe_ratio
                })

                # Check if this is the best combination
                if metric_value > best_metric:
                    best_metric = metric_value
                    best_params = param_dict

                logger.debug("parameter_combination_tested",
                           params=param_dict,
                           metric=optimization_metric,
                           value=metric_value)

            except Exception as e:
                logger.warning("parameter_combination_failed",
                             params=param_dict,
                             error=str(e))

        logger.info("parameter_optimization_completed",
                   best_params=best_params,
                   best_metric=best_metric,
                   combinations_tested=len(results_history))

        return {
            'best_parameters': best_params,
            'best_metric_value': best_metric,
            'optimization_metric': optimization_metric,
            'all_results': results_history
        }


async def test_backtest_engine():
    """Test backtesting functionality."""
    print("📊 Testing Backtest Engine")
    print("=" * 30)

    try:
        # Mock database (in real implementation, would use actual database)
        database = None  # Database()

        # Create backtest engine
        engine = BacktestEngine(database)

        # Configure backtest
        config = BacktestConfig(
            start_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_date=datetime(2024, 1, 31, tzinfo=timezone.utc),
            follow_threshold=70,
            max_position_size=1000.0,
            initial_capital=10000.0
        )

        # Run backtest
        results = await engine.run_backtest(config)

        # Print results
        summary = results.get_performance_summary()
        print("✅ Backtest completed!")
        print(f"  Period: {summary['period']}")
        print(f"  Total return: {summary['returns']['total_return']}")
        print(f"  Win rate: {summary['trades']['win_rate']}")
        print(f"  Sharpe ratio: {summary['returns']['sharpe_ratio']}")
        print(f"  Max drawdown: {summary['returns']['max_drawdown']}")

        print("\n✅ Backtest engine test completed")

    except Exception as e:
        print(f"❌ Test failed: {e}")


if __name__ == "__main__":
    asyncio.run(test_backtest_engine())