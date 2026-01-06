"""
Insider Detection Signals for Witcher's Crystal Ball.

This module contains the core detection logic - the "brain" of the bot.
Each signal detector looks for a specific pattern that might indicate
informed trading. Individually, these signals have false positives.
Combined with proper weighting, they become powerful.

Detection Philosophy:
- Fresh wallets making big bets = suspicious, but could be new whales
- Unusual sizing = suspicious, but could be confident retail
- Niche market focus = suspicious, but could be domain experts
- Timing patterns = suspicious, but could be lucky
- ALL of the above together = very likely informed trading
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional
from enum import Enum

import structlog

from ..config import get_settings, DetectionSettings
from ..polymarket import Trade, Market, WalletPosition

logger = structlog.get_logger()


# =============================================================================
# Signal Types & Results
# =============================================================================

class SignalType(str, Enum):
    """Types of suspicious signals we detect."""
    FRESH_WALLET = "fresh_wallet"
    UNUSUAL_SIZING = "unusual_sizing"
    NICHE_CONCENTRATION = "niche_concentration"
    TIMING_PATTERN = "timing_pattern"
    REPEAT_WINNER = "repeat_winner"


@dataclass
class SignalResult:
    """
    Result of running a signal detector.
    
    Attributes:
        triggered: Whether the signal was detected
        signal_type: Which signal this is
        score: Points contributed to suspicion score (0 if not triggered)
        confidence: How confident we are (0.0 to 1.0)
        details: Human-readable explanation of why it triggered
        metadata: Additional data for logging/analysis
    """
    triggered: bool
    signal_type: SignalType
    score: int = 0
    confidence: float = 0.0
    details: str = ""
    metadata: dict = field(default_factory=dict)
    
    def __str__(self) -> str:
        status = "✓" if self.triggered else "✗"
        return f"{status} {self.signal_type.value}: {self.details} ({self.score}pts)"


@dataclass
class WalletProfile:
    """
    Profile of a wallet built from historical data.
    
    This is what we store in the database and use for detection.
    A wallet's profile tells us if they're "fresh" or established,
    and if they have a history of suspicious winning trades.
    """
    address: str
    first_seen: datetime
    total_trades: int = 0
    total_volume_usd: float = 0.0
    winning_trades: int = 0
    total_resolved_trades: int = 0
    
    @property
    def days_since_first_seen(self) -> float:
        """How many days since we first saw this wallet."""
        delta = datetime.now(timezone.utc) - self.first_seen
        return delta.total_seconds() / 86400  # seconds in a day
    
    @property
    def win_rate(self) -> Optional[float]:
        """Win rate if we have enough data, None otherwise."""
        if self.total_resolved_trades < 3:  # Need minimum sample size
            return None
        return self.winning_trades / self.total_resolved_trades
    
    @property
    def is_fresh(self) -> bool:
        """Check if wallet qualifies as 'fresh' based on settings."""
        settings = get_settings().detection
        return (
            self.days_since_first_seen <= settings.fresh_wallet_threshold_days
            and self.total_trades < settings.fresh_wallet_min_trades
        )


@dataclass
class SuspicionReport:
    """
    Complete analysis of a potentially suspicious trade.
    
    This is what we generate when we detect something worth alerting on.
    Contains all signals, the total score, and context needed for the alert.
    """
    wallet_address: str
    wallet_profile: WalletProfile
    trade: Trade
    market: Market
    
    # Signal results
    signals: list[SignalResult] = field(default_factory=list)
    
    # Computed totals
    total_score: int = 0
    
    # Position context
    position_size_usd: float = 0.0
    position_side: str = "YES"
    price_at_detection: float = 0.0
    
    # Market context
    market_volume_share: float = 0.0  # What % of market volume is this trade?
    hours_until_resolution: Optional[float] = None
    
    @property
    def should_alert(self) -> bool:
        """Check if this report meets the alert threshold."""
        settings = get_settings().detection
        return self.total_score >= settings.alert_threshold_score
    
    @property
    def triggered_signals(self) -> list[SignalResult]:
        """Get only the signals that triggered."""
        return [s for s in self.signals if s.triggered]
    
    def summary(self) -> str:
        """Generate a brief summary for logging."""
        triggered = [s.signal_type.value for s in self.triggered_signals]
        return (
            f"Wallet {self.wallet_address[:10]}... | "
            f"Score: {self.total_score}/100 | "
            f"Signals: {', '.join(triggered) or 'none'}"
        )


# =============================================================================
# Individual Signal Detectors
# =============================================================================

class FreshWalletDetector:
    """
    Detect trades from fresh (new) wallets making significant bets.
    
    Why this matters:
    Insiders often create new wallets to avoid association with their
    main accounts. A brand new wallet making a large, confident bet
    in a specific market is suspicious.
    
    False positive scenarios:
    - New users discovering Polymarket
    - Whales using fresh wallets for privacy (legitimate)
    - Market makers setting up new accounts
    """
    
    def __init__(self, settings: Optional[DetectionSettings] = None):
        self.settings = settings or get_settings().detection
    
    def detect(
        self,
        wallet: WalletProfile,
        trade: Trade,
        market: Market
    ) -> SignalResult:
        """
        Check if this trade triggers the fresh wallet signal.
        
        Triggers when:
        1. Wallet was first seen within threshold days
        2. Wallet has fewer than threshold trades
        3. Trade size exceeds threshold USD
        """
        result = SignalResult(
            triggered=False,
            signal_type=SignalType.FRESH_WALLET,
            score=0
        )
        
        # Check if wallet is fresh
        if not wallet.is_fresh:
            result.details = f"Wallet is established ({wallet.total_trades} trades, {wallet.days_since_first_seen:.1f} days old)"
            return result
        
        # Check if trade size is significant
        if trade.size_usd < self.settings.fresh_wallet_position_threshold_usd:
            result.details = f"Trade size ${trade.size_usd:.2f} below threshold ${self.settings.fresh_wallet_position_threshold_usd}"
            return result
        
        # Signal triggered!
        result.triggered = True
        result.score = self.settings.weight_fresh_wallet
        
        # Calculate confidence based on how fresh and how large
        freshness_factor = 1 - (wallet.days_since_first_seen / self.settings.fresh_wallet_threshold_days)
        size_factor = min(trade.size_usd / (self.settings.fresh_wallet_position_threshold_usd * 5), 1.0)
        result.confidence = (freshness_factor + size_factor) / 2
        
        result.details = (
            f"Fresh wallet ({wallet.days_since_first_seen:.1f} days, "
            f"{wallet.total_trades} trades) betting ${trade.size_usd:.2f}"
        )
        result.metadata = {
            "days_old": wallet.days_since_first_seen,
            "prior_trades": wallet.total_trades,
            "trade_size_usd": trade.size_usd
        }
        
        logger.info(
            "fresh_wallet_detected",
            wallet=wallet.address,
            days_old=wallet.days_since_first_seen,
            trade_size=trade.size_usd
        )
        
        return result


class UnusualSizingDetector:
    """
    Detect trades with unusual position sizing relative to the market.
    
    Why this matters:
    Informed traders often size their positions larger than normal
    because they have higher confidence. A trade that's 10% of daily
    volume or 5% of total liquidity stands out.
    
    False positive scenarios:
    - Market makers rebalancing
    - Whales making normal (for them) trades
    - Low liquidity markets where any trade looks large
    """
    
    def __init__(self, settings: Optional[DetectionSettings] = None):
        self.settings = settings or get_settings().detection
    
    def detect(
        self,
        trade: Trade,
        market: Market,
        median_position_size: Optional[float] = None
    ) -> SignalResult:
        """
        Check if this trade has unusual sizing.
        
        Triggers when ANY of:
        1. Trade > X% of total market liquidity
        2. Trade > X% of 24h volume
        3. Trade > Xx the median position size (if known)
        """
        result = SignalResult(
            triggered=False,
            signal_type=SignalType.UNUSUAL_SIZING,
            score=0
        )
        
        reasons = []
        max_confidence = 0.0
        
        # Check liquidity ratio
        if market.liquidity > 0:
            liquidity_ratio = trade.size_usd / market.liquidity
            if liquidity_ratio > self.settings.liquidity_threshold_pct:
                reasons.append(f"{liquidity_ratio:.1%} of liquidity")
                max_confidence = max(max_confidence, min(liquidity_ratio / 0.2, 1.0))
        
        # Check 24h volume ratio
        if market.volume_24h > 0:
            volume_ratio = trade.size_usd / market.volume_24h
            if volume_ratio > self.settings.volume_threshold_pct:
                reasons.append(f"{volume_ratio:.1%} of 24h volume")
                max_confidence = max(max_confidence, min(volume_ratio / 0.3, 1.0))
        
        # Check median position ratio (if we have data)
        if median_position_size and median_position_size > 0:
            median_ratio = trade.size_usd / median_position_size
            if median_ratio > self.settings.median_position_multiplier:
                reasons.append(f"{median_ratio:.1f}x median size")
                max_confidence = max(max_confidence, min(median_ratio / 10, 1.0))
        
        if not reasons:
            result.details = f"Trade size ${trade.size_usd:.2f} within normal range"
            return result
        
        # Signal triggered!
        result.triggered = True
        result.score = self.settings.weight_unusual_sizing
        result.confidence = max_confidence
        result.details = f"Unusual sizing: {', '.join(reasons)}"
        result.metadata = {
            "trade_size_usd": trade.size_usd,
            "market_liquidity": market.liquidity,
            "market_volume_24h": market.volume_24h,
            "reasons": reasons
        }
        
        logger.info(
            "unusual_sizing_detected",
            wallet=trade.maker,
            market=market.id,
            reasons=reasons
        )
        
        return result


class NicheMarketDetector:
    """
    Detect large positions in low-volume/niche markets.
    
    Why this matters:
    Insiders often have information about niche events that aren't
    widely followed. A large position in a $20k volume market about
    a specific company announcement is more suspicious than the same
    position in a $5M political market.
    
    False positive scenarios:
    - Domain experts who follow specific topics
    - Early traders in new markets
    - Community members of niche topics
    """
    
    def __init__(self, settings: Optional[DetectionSettings] = None):
        self.settings = settings or get_settings().detection
    
    def detect(
        self,
        trade: Trade,
        market: Market,
        wallet_market_share: Optional[float] = None
    ) -> SignalResult:
        """
        Check if this is suspicious niche market activity.
        
        Triggers when:
        1. Market total volume < threshold (it's "niche")
        2. AND wallet position dominates one side (> X%)
        3. AND market resolves within threshold hours (optional boost)
        """
        result = SignalResult(
            triggered=False,
            signal_type=SignalType.NICHE_CONCENTRATION,
            score=0
        )
        
        # Check if market is niche
        if market.volume >= self.settings.niche_market_volume_threshold_usd:
            result.details = f"Market volume ${market.volume:,.0f} above niche threshold"
            return result
        
        # Check position dominance (if we have the data)
        # This requires knowing total YES/NO positions, which we might not have
        # For now, we'll use trade size relative to market volume as a proxy
        dominance_proxy = trade.size_usd / max(market.volume, 1)
        
        if wallet_market_share is not None:
            dominance = wallet_market_share
        else:
            dominance = dominance_proxy
        
        if dominance < self.settings.position_dominance_threshold_pct:
            result.details = f"Position {dominance:.1%} doesn't dominate market"
            return result
        
        # Signal triggered!
        result.triggered = True
        result.score = self.settings.weight_niche_concentration
        
        # Boost confidence if resolution is imminent
        confidence = min(dominance / 0.5, 1.0)  # Base confidence from dominance
        
        if market.hours_until_resolution is not None:
            if market.hours_until_resolution <= self.settings.resolution_window_hours:
                # Closer to resolution = more suspicious
                time_factor = 1 - (market.hours_until_resolution / self.settings.resolution_window_hours)
                confidence = (confidence + time_factor) / 2
                result.metadata["resolution_boost"] = True
        
        result.confidence = confidence
        result.details = (
            f"Niche market (${market.volume:,.0f} volume), "
            f"{dominance:.1%} position dominance"
        )
        result.metadata.update({
            "market_volume": market.volume,
            "position_dominance": dominance,
            "hours_until_resolution": market.hours_until_resolution
        })
        
        logger.info(
            "niche_concentration_detected",
            wallet=trade.maker,
            market=market.id,
            volume=market.volume,
            dominance=dominance
        )
        
        return result


class TimingPatternDetector:
    """
    Detect suspicious timing patterns in trading activity.
    
    Why this matters:
    Insiders often trade close to event resolution because:
    1. They want to minimize time their capital is locked
    2. Information leaks tend to happen close to announcements
    3. Less time for the market to price in the information
    
    False positive scenarios:
    - Traders reacting to public news close to deadline
    - Last-minute conviction trades
    - Time zone differences making trades appear "last minute"
    """
    
    def __init__(self, settings: Optional[DetectionSettings] = None):
        self.settings = settings or get_settings().detection
    
    def detect(
        self,
        trade: Trade,
        market: Market,
        wallet_timing_history: Optional[list[tuple[float, bool]]] = None
    ) -> SignalResult:
        """
        Check for suspicious timing patterns.
        
        Triggers when:
        1. Trade placed within X hours of resolution
        2. (Optional) Wallet has history of last-minute winning trades
        
        Args:
            trade: The trade to analyze
            market: The market being traded
            wallet_timing_history: List of (hours_before_resolution, won) tuples
        """
        result = SignalResult(
            triggered=False,
            signal_type=SignalType.TIMING_PATTERN,
            score=0
        )
        
        # Check if we know when the market resolves
        if market.hours_until_resolution is None:
            result.details = "Resolution time unknown, can't assess timing"
            return result
        
        # Check if this is a "last minute" trade
        if market.hours_until_resolution > self.settings.last_minute_threshold_hours:
            result.details = f"{market.hours_until_resolution:.1f}h until resolution (not last-minute)"
            return result
        
        # Signal triggered!
        result.triggered = True
        result.score = self.settings.weight_timing_pattern
        
        # Base confidence from how close to resolution
        time_ratio = market.hours_until_resolution / self.settings.last_minute_threshold_hours
        confidence = 1 - time_ratio  # Closer = more confident
        
        # Boost if wallet has history of last-minute winners
        if wallet_timing_history:
            last_minute_wins = sum(
                1 for hours, won in wallet_timing_history
                if hours <= self.settings.last_minute_threshold_hours and won
            )
            last_minute_total = sum(
                1 for hours, _ in wallet_timing_history
                if hours <= self.settings.last_minute_threshold_hours
            )
            
            if last_minute_total >= 3:  # Need minimum sample
                historical_win_rate = last_minute_wins / last_minute_total
                if historical_win_rate > 0.6:  # Better than chance
                    confidence = min(confidence + 0.2, 1.0)
                    result.metadata["historical_boost"] = True
                    result.metadata["last_minute_win_rate"] = historical_win_rate
        
        result.confidence = confidence
        result.details = f"Trade {market.hours_until_resolution:.1f}h before resolution"
        result.metadata.update({
            "hours_until_resolution": market.hours_until_resolution,
            "threshold_hours": self.settings.last_minute_threshold_hours
        })
        
        logger.info(
            "timing_pattern_detected",
            wallet=trade.maker,
            market=market.id,
            hours_until_resolution=market.hours_until_resolution
        )
        
        return result


class RepeatWinnerDetector:
    """
    Detect wallets with suspiciously high win rates.
    
    Why this matters:
    A wallet that consistently wins, especially on low-probability bets,
    might have access to inside information. Random chance would give
    ~50% win rate; consistent 70%+ is unusual.
    
    False positive scenarios:
    - Skilled traders/analysts
    - Small sample sizes (got lucky a few times)
    - Conservative traders who only bet on "sure things"
    """
    
    def __init__(self, settings: Optional[DetectionSettings] = None):
        self.settings = settings or get_settings().detection
    
    def detect(
        self,
        wallet: WalletProfile,
        trade: Trade
    ) -> SignalResult:
        """
        Check if this wallet has a suspiciously high win rate.
        
        Triggers when:
        1. Wallet has sufficient trade history (3+ resolved)
        2. Win rate exceeds threshold (e.g., 70%)
        """
        result = SignalResult(
            triggered=False,
            signal_type=SignalType.REPEAT_WINNER,
            score=0
        )
        
        # Need sufficient history
        if wallet.win_rate is None:
            result.details = f"Insufficient history ({wallet.total_resolved_trades} resolved trades)"
            return result
        
        # Check win rate threshold
        # We use 65% as "suspicious" - significantly better than chance
        win_rate_threshold = 0.65
        
        if wallet.win_rate < win_rate_threshold:
            result.details = f"Win rate {wallet.win_rate:.1%} within normal range"
            return result
        
        # Signal triggered!
        result.triggered = True
        result.score = self.settings.weight_repeat_winner
        
        # Confidence scales with sample size and win rate
        sample_factor = min(wallet.total_resolved_trades / 20, 1.0)  # More trades = more confident
        win_factor = (wallet.win_rate - 0.5) / 0.5  # How much above 50%
        result.confidence = (sample_factor + win_factor) / 2
        
        result.details = (
            f"High win rate: {wallet.win_rate:.1%} "
            f"({wallet.winning_trades}/{wallet.total_resolved_trades})"
        )
        result.metadata = {
            "win_rate": wallet.win_rate,
            "winning_trades": wallet.winning_trades,
            "total_resolved": wallet.total_resolved_trades
        }
        
        logger.info(
            "repeat_winner_detected",
            wallet=wallet.address,
            win_rate=wallet.win_rate,
            resolved_trades=wallet.total_resolved_trades
        )
        
        return result


# =============================================================================
# Main Analyzer (Combines All Signals)
# =============================================================================

class InsiderDetector:
    """
    Main analyzer that combines all detection signals.
    
    Usage:
        detector = InsiderDetector()
        report = detector.analyze(wallet_profile, trade, market)
        if report.should_alert:
            send_alert(report)
    """
    
    def __init__(self, settings: Optional[DetectionSettings] = None):
        self.settings = settings or get_settings().detection
        
        # Initialize all detectors
        self.fresh_wallet = FreshWalletDetector(self.settings)
        self.unusual_sizing = UnusualSizingDetector(self.settings)
        self.niche_market = NicheMarketDetector(self.settings)
        self.timing_pattern = TimingPatternDetector(self.settings)
        self.repeat_winner = RepeatWinnerDetector(self.settings)
    
    def analyze(
        self,
        wallet: WalletProfile,
        trade: Trade,
        market: Market,
        median_position_size: Optional[float] = None,
        wallet_market_share: Optional[float] = None,
        wallet_timing_history: Optional[list[tuple[float, bool]]] = None
    ) -> SuspicionReport:
        """
        Run all detectors and generate a complete suspicion report.
        
        Args:
            wallet: Profile of the wallet making the trade
            trade: The trade to analyze
            market: The market being traded
            median_position_size: Median position size in this market (for sizing signal)
            wallet_market_share: Wallet's share of one side (for niche signal)
            wallet_timing_history: Past (hours_before_resolution, won) data
            
        Returns:
            SuspicionReport with all signals and total score
        """
        report = SuspicionReport(
            wallet_address=wallet.address,
            wallet_profile=wallet,
            trade=trade,
            market=market,
            position_size_usd=trade.size_usd,
            position_side="YES" if trade.price > 0.5 else "NO",  # Simplified
            price_at_detection=trade.price,
            hours_until_resolution=market.hours_until_resolution
        )
        
        # Calculate market volume share
        if market.volume_24h > 0:
            report.market_volume_share = trade.size_usd / market.volume_24h
        
        # Run all detectors
        signals = [
            self.fresh_wallet.detect(wallet, trade, market),
            self.unusual_sizing.detect(trade, market, median_position_size),
            self.niche_market.detect(trade, market, wallet_market_share),
            self.timing_pattern.detect(trade, market, wallet_timing_history),
            self.repeat_winner.detect(wallet, trade)
        ]
        
        report.signals = signals
        report.total_score = sum(s.score for s in signals)
        
        # Log the analysis
        logger.info(
            "analysis_complete",
            wallet=wallet.address[:10],
            market=market.id[:10] if market.id else "unknown",
            total_score=report.total_score,
            triggered_signals=[s.signal_type.value for s in report.triggered_signals],
            should_alert=report.should_alert
        )
        
        return report
    
    def quick_scan(
        self,
        wallet: WalletProfile,
        trade: Trade,
        market: Market
    ) -> bool:
        """
        Quick check if a trade is worth full analysis.
        
        Use this to filter trades before doing expensive database lookups
        for additional context (median sizes, timing history, etc.)
        
        Returns True if the trade should be fully analyzed.
        """
        # Skip if wallet is well-established
        if wallet.total_trades > 20 and wallet.days_since_first_seen > 30:
            return False
        
        # Skip tiny trades
        if trade.size_usd < 100:
            return False
        
        # Skip huge, well-known markets (unless trade is massive)
        if market.volume > 1_000_000 and trade.size_usd < 5000:
            return False
        
        return True


# =============================================================================
# Quick Test
# =============================================================================

def _test_signals():
    """Test the signal detectors with mock data."""
    from rich import print as rprint
    from rich.panel import Panel
    from rich.table import Table
    
    # Create mock data
    fresh_wallet = WalletProfile(
        address="0x1234567890abcdef1234567890abcdef12345678",
        first_seen=datetime.now(timezone.utc) - timedelta(days=2),
        total_trades=3,
        total_volume_usd=1500.0
    )
    
    established_wallet = WalletProfile(
        address="0xabcdef1234567890abcdef1234567890abcdef12",
        first_seen=datetime.now(timezone.utc) - timedelta(days=90),
        total_trades=150,
        total_volume_usd=50000.0,
        winning_trades=35,
        total_resolved_trades=45
    )
    
    niche_market = Market(
        id="0xniche",
        question="Will obscure company X announce Y?",
        volume=25000,
        volume_24h=3000,
        liquidity=8000,
        end_date=datetime.now(timezone.utc) + timedelta(hours=12)
    )
    
    large_trade = Trade(
        id="trade1",
        market="0xniche",
        maker=fresh_wallet.address,
        taker="0xtaker",
        side="BUY",
        size=10000,
        price=0.08,
        timestamp=datetime.now(timezone.utc)
    )
    
    # Run detection
    detector = InsiderDetector()
    report = detector.analyze(
        wallet=fresh_wallet,
        trade=large_trade,
        market=niche_market
    )
    
    # Display results
    rprint(Panel.fit(
        f"[bold]Analysis: {report.wallet_address[:20]}...[/bold]\n\n"
        f"Trade: ${report.position_size_usd:.2f} at {report.price_at_detection:.1%}\n"
        f"Market: {report.market.question[:40]}...\n"
        f"Hours to resolution: {report.hours_until_resolution:.1f}h",
        title="🔮 Suspicion Report"
    ))
    
    # Signals table
    table = Table(title=f"Total Score: {report.total_score}/100")
    table.add_column("Signal", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Score", style="yellow")
    table.add_column("Details", style="white")
    
    for signal in report.signals:
        status = "✓ TRIGGERED" if signal.triggered else "✗ Clear"
        status_style = "bold red" if signal.triggered else "dim"
        table.add_row(
            signal.signal_type.value,
            f"[{status_style}]{status}[/{status_style}]",
            str(signal.score),
            signal.details[:50]
        )
    
    rprint(table)
    
    alert_msg = "[bold green]✓ ALERT TRIGGERED[/bold green]" if report.should_alert else "[dim]Below threshold[/dim]"
    rprint(f"\nShould Alert: {alert_msg}")


if __name__ == "__main__":
    _test_signals()