"""
Database Layer for Witcher's Crystal Ball.

This module handles all persistent storage using SQLite.
We use async SQLite (aiosqlite) to not block the event loop
while the bot is scanning for new trades.

Database Design Philosophy:
1. Track ALL wallets we see, not just suspicious ones
   - Builds history over time
   - Allows retroactive analysis ("was this wallet fresh when it made that winning bet?")

2. Store alerts separately from performance
   - Alerts = what we detected
   - Performance = did following the alert make money?
   - Separating these lets us analyze detection accuracy

3. Use simple schema, optimize later if needed
   - SQLite is fast enough for our use case
   - Premature optimization is the root of all evil
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

import aiosqlite
import structlog

from ..config import get_settings
from ..detection.signals import WalletProfile, SuspicionReport, SignalType

logger = structlog.get_logger()


# =============================================================================
# Database Schema
# =============================================================================

SCHEMA = """
-- Wallets table: Track every wallet we observe
-- This builds our historical baseline for "fresh" detection
CREATE TABLE IF NOT EXISTS wallets (
    address TEXT PRIMARY KEY,
    first_seen TIMESTAMP NOT NULL,
    total_trades INTEGER DEFAULT 0,
    total_volume_usd REAL DEFAULT 0.0,
    winning_trades INTEGER DEFAULT 0,
    total_resolved_trades INTEGER DEFAULT 0,
    last_updated TIMESTAMP NOT NULL,
    
    -- Denormalized stats for quick queries
    avg_trade_size_usd REAL DEFAULT 0.0,
    largest_trade_usd REAL DEFAULT 0.0
);

-- Index for finding fresh wallets quickly
CREATE INDEX IF NOT EXISTS idx_wallets_first_seen ON wallets(first_seen);
CREATE INDEX IF NOT EXISTS idx_wallets_total_trades ON wallets(total_trades);


-- Alerts table: Every suspicious activity we detect
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- What triggered the alert
    wallet_address TEXT NOT NULL,
    market_id TEXT NOT NULL,
    market_question TEXT,
    event_slug TEXT,
    
    -- Detection details
    signal_types TEXT NOT NULL,  -- Comma-separated list of triggered signals
    suspicion_score INTEGER NOT NULL,
    
    -- Position details at time of alert
    position_size_usd REAL NOT NULL,
    position_side TEXT NOT NULL,  -- 'YES' or 'NO'
    entry_price REAL NOT NULL,
    
    -- Market context at time of alert
    market_volume REAL,
    market_liquidity REAL,
    hours_until_resolution REAL,
    
    -- Timestamps
    created_at TIMESTAMP NOT NULL,
    trade_timestamp TIMESTAMP,
    
    -- Resolution tracking
    resolved_at TIMESTAMP,
    resolution_price REAL,  -- Final price (0 or 1)
    outcome TEXT,  -- 'WIN', 'LOSS', or NULL if pending
    
    -- Foreign key (soft, SQLite doesn't enforce by default)
    FOREIGN KEY (wallet_address) REFERENCES wallets(address)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_alerts_wallet ON alerts(wallet_address);
CREATE INDEX IF NOT EXISTS idx_alerts_market ON alerts(market_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_outcome ON alerts(outcome);
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(suspicion_score);


-- Performance table: Track if we acted on alerts and the results
-- This is separate because not every alert results in a trade
CREATE TABLE IF NOT EXISTS performance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    
    -- Our trade details (if we followed the alert)
    our_entry_price REAL,
    our_entry_size_usd REAL,
    our_exit_price REAL,
    
    -- Results
    pnl_usd REAL,
    pnl_percent REAL,
    
    -- Timestamps
    entry_timestamp TIMESTAMP,
    exit_timestamp TIMESTAMP,
    
    -- Notes
    notes TEXT,
    
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);


-- Market cache: Store market metadata to avoid repeated API calls
CREATE TABLE IF NOT EXISTS market_cache (
    id TEXT PRIMARY KEY,
    question TEXT,
    slug TEXT,
    event_id TEXT,
    event_slug TEXT,
    
    -- Metadata
    volume REAL,
    liquidity REAL,
    end_date TIMESTAMP,
    
    -- Cache management
    cached_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_market_cache_expires ON market_cache(expires_at);


-- Trade history: Optional detailed trade log for backtesting
-- This can grow large, so it's optional and can be pruned
CREATE TABLE IF NOT EXISTS trade_history (
    id TEXT PRIMARY KEY,
    market_id TEXT NOT NULL,
    maker TEXT NOT NULL,
    taker TEXT,
    side TEXT NOT NULL,
    size REAL NOT NULL,
    price REAL NOT NULL,
    size_usd REAL NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    
    -- When we recorded this
    recorded_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_trades_market ON trade_history(market_id);
CREATE INDEX IF NOT EXISTS idx_trades_maker ON trade_history(maker);
CREATE INDEX IF NOT EXISTS idx_trades_timestamp ON trade_history(timestamp);
"""


# =============================================================================
# Database Manager
# =============================================================================

class Database:
    """
    Async database manager for Witcher's Crystal Ball.
    
    Handles all database operations with proper connection management.
    Uses connection pooling via context managers to handle concurrent access.
    
    Usage:
        db = Database()
        await db.initialize()
        
        wallet = await db.get_wallet("0x...")
        await db.save_alert(report)
        
        await db.close()
    
    Or with context manager:
        async with Database() as db:
            wallet = await db.get_wallet("0x...")
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize database manager.
        
        Args:
            db_path: Path to SQLite database. If None, uses config default.
        """
        self.db_path = db_path or get_settings().database_path
        self._connection: Optional[aiosqlite.Connection] = None
    
    async def __aenter__(self) -> "Database":
        """Async context manager entry."""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()
    
    async def initialize(self) -> None:
        """
        Initialize the database connection and create tables.
        
        Creates the database file and directory if they don't exist.
        Runs migrations (creates tables) on every startup.
        """
        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Open connection
        self._connection = await aiosqlite.connect(self.db_path)
        
        # Enable foreign keys (SQLite has them disabled by default)
        await self._connection.execute("PRAGMA foreign_keys = ON")
        
        # Use WAL mode for better concurrent read/write performance
        await self._connection.execute("PRAGMA journal_mode = WAL")
        
        # Run schema creation (idempotent due to IF NOT EXISTS)
        await self._connection.executescript(SCHEMA)
        await self._connection.commit()
        
        logger.info("database_initialized", path=str(self.db_path))
    
    async def close(self) -> None:
        """Close database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None
            logger.debug("database_closed")
    
    @asynccontextmanager
    async def _get_cursor(self):
        """Get a cursor with automatic cleanup."""
        if not self._connection:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        cursor = await self._connection.cursor()
        try:
            yield cursor
        finally:
            await cursor.close()
    
    # =========================================================================
    # Wallet Operations
    # =========================================================================
    
    async def get_wallet(self, address: str) -> Optional[WalletProfile]:
        """
        Get wallet profile by address.
        
        Returns None if wallet hasn't been seen before.
        """
        async with self._get_cursor() as cursor:
            await cursor.execute(
                """
                SELECT address, first_seen, total_trades, total_volume_usd,
                       winning_trades, total_resolved_trades
                FROM wallets
                WHERE address = ?
                """,
                (address.lower(),)  # Normalize to lowercase
            )
            row = await cursor.fetchone()
        
        if not row:
            return None
        
        return WalletProfile(
            address=row[0],
            first_seen=datetime.fromisoformat(row[1]),
            total_trades=row[2],
            total_volume_usd=row[3],
            winning_trades=row[4],
            total_resolved_trades=row[5]
        )
    
    async def get_or_create_wallet(self, address: str) -> WalletProfile:
        """
        Get existing wallet or create new one.
        
        This is the main method to use when processing trades.
        If the wallet doesn't exist, it's created with first_seen = now.
        """
        address = address.lower()  # Normalize
        
        wallet = await self.get_wallet(address)
        if wallet:
            return wallet
        
        # Create new wallet
        now = datetime.now(timezone.utc)
        async with self._get_cursor() as cursor:
            await cursor.execute(
                """
                INSERT INTO wallets (address, first_seen, last_updated)
                VALUES (?, ?, ?)
                ON CONFLICT(address) DO NOTHING
                """,
                (address, now.isoformat(), now.isoformat())
            )
            await self._connection.commit()
        
        logger.debug("wallet_created", address=address[:10])
        
        return WalletProfile(
            address=address,
            first_seen=now,
            total_trades=0,
            total_volume_usd=0.0
        )
    
    async def update_wallet_stats(
        self,
        address: str,
        trade_size_usd: float,
        won: Optional[bool] = None
    ) -> None:
        """
        Update wallet statistics after a trade.
        
        Args:
            address: Wallet address
            trade_size_usd: Size of the trade in USD
            won: If the trade resolved, did they win? None if not resolved yet.
        """
        address = address.lower()
        now = datetime.now(timezone.utc)
        
        async with self._get_cursor() as cursor:
            # Update basic stats
            await cursor.execute(
                """
                UPDATE wallets
                SET total_trades = total_trades + 1,
                    total_volume_usd = total_volume_usd + ?,
                    largest_trade_usd = MAX(largest_trade_usd, ?),
                    last_updated = ?
                WHERE address = ?
                """,
                (trade_size_usd, trade_size_usd, now.isoformat(), address)
            )
            
            # Update win/loss if resolved
            if won is not None:
                if won:
                    await cursor.execute(
                        """
                        UPDATE wallets
                        SET winning_trades = winning_trades + 1,
                            total_resolved_trades = total_resolved_trades + 1
                        WHERE address = ?
                        """,
                        (address,)
                    )
                else:
                    await cursor.execute(
                        """
                        UPDATE wallets
                        SET total_resolved_trades = total_resolved_trades + 1
                        WHERE address = ?
                        """,
                        (address,)
                    )
            
            await self._connection.commit()
    
    async def get_fresh_wallets(
        self,
        days: int = 7,
        min_trades: int = 5,
        limit: int = 100
    ) -> list[WalletProfile]:
        """
        Get wallets that qualify as "fresh" (new and low activity).
        
        Useful for analysis and monitoring.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        
        async with self._get_cursor() as cursor:
            await cursor.execute(
                """
                SELECT address, first_seen, total_trades, total_volume_usd,
                       winning_trades, total_resolved_trades
                FROM wallets
                WHERE first_seen >= ? AND total_trades < ?
                ORDER BY first_seen DESC
                LIMIT ?
                """,
                (cutoff.isoformat(), min_trades, limit)
            )
            rows = await cursor.fetchall()
        
        return [
            WalletProfile(
                address=row[0],
                first_seen=datetime.fromisoformat(row[1]),
                total_trades=row[2],
                total_volume_usd=row[3],
                winning_trades=row[4],
                total_resolved_trades=row[5]
            )
            for row in rows
        ]
    
    # =========================================================================
    # Alert Operations
    # =========================================================================
    
    async def save_alert(self, report: SuspicionReport) -> int:
        """
        Save a suspicion report as an alert.
        
        Returns the alert ID for tracking.
        """
        now = datetime.now(timezone.utc)
        triggered_signals = ",".join(s.signal_type.value for s in report.triggered_signals)
        
        async with self._get_cursor() as cursor:
            await cursor.execute(
                """
                INSERT INTO alerts (
                    wallet_address, market_id, market_question, event_slug,
                    signal_types, suspicion_score,
                    position_size_usd, position_side, entry_price,
                    market_volume, market_liquidity, hours_until_resolution,
                    created_at, trade_timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.wallet_address.lower(),
                    report.market.id,
                    report.market.question,
                    report.market.event_slug,
                    triggered_signals,
                    report.total_score,
                    report.position_size_usd,
                    report.position_side,
                    report.price_at_detection,
                    report.market.volume,
                    report.market.liquidity,
                    report.hours_until_resolution,
                    now.isoformat(),
                    report.trade.timestamp.isoformat()
                )
            )
            await self._connection.commit()
            alert_id = cursor.lastrowid
        
        logger.info(
            "alert_saved",
            alert_id=alert_id,
            wallet=report.wallet_address[:10],
            score=report.total_score
        )
        
        return alert_id
    
    async def get_alert(self, alert_id: int) -> Optional[dict]:
        """Get alert by ID."""
        async with self._get_cursor() as cursor:
            await cursor.execute(
                "SELECT * FROM alerts WHERE id = ?",
                (alert_id,)
            )
            row = await cursor.fetchone()
            
            if not row:
                return None
            
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))
    
    async def get_pending_alerts(self, limit: int = 100) -> list[dict]:
        """Get alerts that haven't been resolved yet."""
        async with self._get_cursor() as cursor:
            await cursor.execute(
                """
                SELECT * FROM alerts
                WHERE outcome IS NULL
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,)
            )
            rows = await cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            
        return [dict(zip(columns, row)) for row in rows]
    
    async def update_alert_outcome(
        self,
        alert_id: int,
        resolution_price: float,
        outcome: str  # 'WIN' or 'LOSS'
    ) -> None:
        """Update alert with resolution outcome and update wallet win rate."""
        now = datetime.now(timezone.utc)

        async with self._get_cursor() as cursor:
            # Get the alert to find the wallet address
            await cursor.execute(
                "SELECT wallet_address FROM alerts WHERE id = ?",
                (alert_id,)
            )
            row = await cursor.fetchone()

            if not row:
                logger.warning("alert_not_found", alert_id=alert_id)
                return

            wallet_address = row[0]

            # Update alert with outcome
            await cursor.execute(
                """
                UPDATE alerts
                SET resolved_at = ?,
                    resolution_price = ?,
                    outcome = ?
                WHERE id = ?
                """,
                (now.isoformat(), resolution_price, outcome, alert_id)
            )

            # Update wallet win/loss stats
            won = (outcome == 'WIN')
            await self.update_wallet_stats(wallet_address, 0.0, won)

            await self._connection.commit()

        logger.info("alert_resolved", alert_id=alert_id, outcome=outcome, wallet=wallet_address[:10])
    
    async def get_alerts_for_wallet(
        self,
        address: str,
        limit: int = 50
    ) -> list[dict]:
        """Get all alerts for a specific wallet."""
        async with self._get_cursor() as cursor:
            await cursor.execute(
                """
                SELECT * FROM alerts
                WHERE wallet_address = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (address.lower(), limit)
            )
            rows = await cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            
        return [dict(zip(columns, row)) for row in rows]
    
    async def get_recent_alerts(
        self,
        hours: int = 24,
        min_score: int = 0,
        limit: int = 100
    ) -> list[dict]:
        """Get recent alerts, optionally filtered by minimum score."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        async with self._get_cursor() as cursor:
            await cursor.execute(
                """
                SELECT * FROM alerts
                WHERE created_at >= ? AND suspicion_score >= ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (cutoff.isoformat(), min_score, limit)
            )
            rows = await cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            
        return [dict(zip(columns, row)) for row in rows]
    
    # =========================================================================
    # Performance Tracking
    # =========================================================================
    
    async def record_performance(
        self,
        alert_id: int,
        entry_price: float,
        entry_size_usd: float,
        exit_price: Optional[float] = None,
        pnl_usd: Optional[float] = None,
        notes: Optional[str] = None
    ) -> int:
        """
        Record performance data for an alert we acted on.
        
        Call this when you:
        1. Enter a position based on an alert
        2. Exit the position (update with exit_price and pnl)
        """
        now = datetime.now(timezone.utc)
        
        pnl_percent = None
        if pnl_usd is not None and entry_size_usd > 0:
            pnl_percent = (pnl_usd / entry_size_usd) * 100
        
        async with self._get_cursor() as cursor:
            await cursor.execute(
                """
                INSERT INTO performance (
                    alert_id, our_entry_price, our_entry_size_usd,
                    our_exit_price, pnl_usd, pnl_percent,
                    entry_timestamp, exit_timestamp, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    entry_price,
                    entry_size_usd,
                    exit_price,
                    pnl_usd,
                    pnl_percent,
                    now.isoformat(),
                    now.isoformat() if exit_price else None,
                    notes
                )
            )
            await self._connection.commit()
            return cursor.lastrowid
    
    async def get_performance_summary(self) -> dict:
        """
        Get aggregate performance statistics.
        
        Returns summary of all tracked trades.
        """
        async with self._get_cursor() as cursor:
            await cursor.execute(
                """
                SELECT 
                    COUNT(*) as total_trades,
                    SUM(CASE WHEN pnl_usd > 0 THEN 1 ELSE 0 END) as winning_trades,
                    SUM(CASE WHEN pnl_usd < 0 THEN 1 ELSE 0 END) as losing_trades,
                    SUM(pnl_usd) as total_pnl,
                    AVG(pnl_usd) as avg_pnl,
                    AVG(pnl_percent) as avg_pnl_percent,
                    MAX(pnl_usd) as best_trade,
                    MIN(pnl_usd) as worst_trade
                FROM performance
                WHERE pnl_usd IS NOT NULL
                """
            )
            row = await cursor.fetchone()
        
        if not row or row[0] == 0:
            return {
                "total_trades": 0,
                "winning_trades": 0,
                "losing_trades": 0,
                "win_rate": 0.0,
                "total_pnl": 0.0,
                "avg_pnl": 0.0,
                "avg_pnl_percent": 0.0,
                "best_trade": 0.0,
                "worst_trade": 0.0
            }
        
        total = row[0]
        winning = row[1] or 0
        
        return {
            "total_trades": total,
            "winning_trades": winning,
            "losing_trades": row[2] or 0,
            "win_rate": (winning / total * 100) if total > 0 else 0.0,
            "total_pnl": row[3] or 0.0,
            "avg_pnl": row[4] or 0.0,
            "avg_pnl_percent": row[5] or 0.0,
            "best_trade": row[6] or 0.0,
            "worst_trade": row[7] or 0.0
        }
    
    # =========================================================================
    # Trade History (Optional, for backtesting)
    # =========================================================================
    
    async def save_trade(
        self,
        trade_id: str,
        market_id: str,
        maker: str,
        taker: Optional[str],
        side: str,
        size: float,
        price: float,
        timestamp: datetime
    ) -> None:
        """Save a trade to history (for backtesting)."""
        now = datetime.now(timezone.utc)
        size_usd = size * price
        
        async with self._get_cursor() as cursor:
            await cursor.execute(
                """
                INSERT OR IGNORE INTO trade_history (
                    id, market_id, maker, taker, side, size, price, size_usd,
                    timestamp, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    trade_id,
                    market_id,
                    maker.lower(),
                    taker.lower() if taker else None,
                    side,
                    size,
                    price,
                    size_usd,
                    timestamp.isoformat(),
                    now.isoformat()
                )
            )
            await self._connection.commit()
    
    async def get_wallet_timing_history(
        self,
        address: str,
        limit: int = 50
    ) -> list[tuple[float, bool]]:
        """
        Get wallet's historical timing data for timing pattern detection.

        Returns list of (hours_before_resolution, won) tuples.

        Uses the alerts table to get resolved trades with timing data.
        """
        async with self._get_cursor() as cursor:
            await cursor.execute(
                """
                SELECT hours_until_resolution, outcome
                FROM alerts
                WHERE wallet_address = ?
                  AND hours_until_resolution IS NOT NULL
                  AND outcome IS NOT NULL
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (address.lower(), limit)
            )
            rows = await cursor.fetchall()

        timing_data = []
        for row in rows:
            hours_until_resolution, outcome = row
            won = (outcome == 'WIN')
            timing_data.append((hours_until_resolution, won))

        return timing_data
    
    # =========================================================================
    # Statistics & Analysis
    # =========================================================================
    
    async def get_alert_statistics(self) -> dict:
        """Get aggregate statistics about alerts."""
        async with self._get_cursor() as cursor:
            # Total alerts
            await cursor.execute("SELECT COUNT(*) FROM alerts")
            total = (await cursor.fetchone())[0]
            
            # By outcome
            await cursor.execute(
                """
                SELECT outcome, COUNT(*) 
                FROM alerts 
                WHERE outcome IS NOT NULL 
                GROUP BY outcome
                """
            )
            outcomes = dict(await cursor.fetchall())
            
            # By signal type
            await cursor.execute(
                "SELECT signal_types FROM alerts"
            )
            rows = await cursor.fetchall()
            
        signal_counts = {}
        for row in rows:
            for signal in row[0].split(","):
                signal = signal.strip()
                if signal:
                    signal_counts[signal] = signal_counts.get(signal, 0) + 1
        
        wins = outcomes.get("WIN", 0)
        losses = outcomes.get("LOSS", 0)
        resolved = wins + losses
        
        return {
            "total_alerts": total,
            "resolved_alerts": resolved,
            "pending_alerts": total - resolved,
            "wins": wins,
            "losses": losses,
            "win_rate": (wins / resolved * 100) if resolved > 0 else 0.0,
            "signal_frequency": signal_counts
        }
    
    async def cleanup_old_data(self, days: int = 90) -> dict:
        """
        Clean up old data to prevent database bloat.
        
        Removes:
        - Trade history older than X days
        - Resolved alerts older than X days (keeps unresolved)
        
        Returns count of deleted records.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        deleted = {"trades": 0, "alerts": 0}
        
        async with self._get_cursor() as cursor:
            # Delete old trade history
            await cursor.execute(
                "DELETE FROM trade_history WHERE timestamp < ?",
                (cutoff.isoformat(),)
            )
            deleted["trades"] = cursor.rowcount
            
            # Delete old resolved alerts (keep pending ones)
            await cursor.execute(
                """
                DELETE FROM alerts 
                WHERE resolved_at IS NOT NULL AND resolved_at < ?
                """,
                (cutoff.isoformat(),)
            )
            deleted["alerts"] = cursor.rowcount
            
            await self._connection.commit()
        
        logger.info("cleanup_complete", deleted=deleted)
        return deleted


# =============================================================================
# Convenience Functions
# =============================================================================

# Import timedelta for the convenience function
from datetime import timedelta

async def _test_database():
    """Test database operations."""
    from rich import print as rprint
    from rich.panel import Panel
    from rich.table import Table
    
    # Use a test database
    test_db_path = Path("data/test_crystal_ball.db")
    
    rprint(Panel.fit(
        f"[bold]Testing Database[/bold]\n\nPath: {test_db_path}",
        title="🗄️ Database Test"
    ))
    
    async with Database(test_db_path) as db:
        # Test wallet operations
        rprint("\n[yellow]Testing wallet operations...[/yellow]")
        
        wallet = await db.get_or_create_wallet("0x1234567890abcdef")
        rprint(f"Created wallet: {wallet.address[:10]}...")
        rprint(f"  First seen: {wallet.first_seen}")
        rprint(f"  Is fresh: {wallet.is_fresh}")
        
        # Update stats
        await db.update_wallet_stats("0x1234567890abcdef", 500.0)
        wallet = await db.get_wallet("0x1234567890abcdef")
        rprint(f"  After trade: {wallet.total_trades} trades, ${wallet.total_volume_usd} volume")
        
        # Test alert operations
        rprint("\n[yellow]Testing alert operations...[/yellow]")
        
        # Create a mock report (simplified)
        from ..polymarket import Trade, Market
        
        mock_trade = Trade(
            id="test_trade",
            market="0xmarket",
            maker="0x1234567890abcdef",
            taker="0xtaker",
            side="BUY",
            size=1000,
            price=0.1,
            timestamp=datetime.now(timezone.utc)
        )
        
        mock_market = Market(
            id="0xmarket",
            question="Test market question?",
            volume=50000,
            liquidity=10000
        )
        
        # We need to create a proper SuspicionReport
        from ..detection.signals import SignalResult, SignalType
        
        mock_report = SuspicionReport(
            wallet_address="0x1234567890abcdef",
            wallet_profile=wallet,
            trade=mock_trade,
            market=mock_market,
            signals=[
                SignalResult(True, SignalType.FRESH_WALLET, 25, 0.8, "Fresh wallet"),
                SignalResult(True, SignalType.NICHE_CONCENTRATION, 25, 0.7, "Niche market")
            ],
            total_score=50,
            position_size_usd=100,
            position_side="YES",
            price_at_detection=0.1
        )
        
        alert_id = await db.save_alert(mock_report)
        rprint(f"Created alert ID: {alert_id}")
        
        # Get recent alerts
        recent = await db.get_recent_alerts(hours=24)
        rprint(f"Recent alerts: {len(recent)}")
        
        # Get statistics
        stats = await db.get_alert_statistics()
        
        table = Table(title="Alert Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in stats.items():
            if isinstance(value, dict):
                value = str(value)
            elif isinstance(value, float):
                value = f"{value:.1f}"
            table.add_row(key, str(value))
        
        rprint(table)
    
    # Cleanup test database
    test_db_path.unlink(missing_ok=True)
    rprint("\n[green]✓ Database test complete![/green]")


if __name__ == "__main__":
    asyncio.run(_test_database())