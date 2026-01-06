"""
Witcher's Crystal Ball - Main Entry Point

This is the orchestration layer that ties everything together:
1. Fetches new trades from Polymarket
2. Runs detection signals on each trade
3. Saves alerts to database
4. Sends Telegram notifications

Run with:
    python -m src.main

Or for development:
    python src/main.py --debug
"""

import asyncio
import signal
from datetime import datetime, timezone, timedelta
from typing import Optional, Set

import structlog
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

# Proper package imports
from .config import get_settings
from .polymarket import PolymarketClient, Trade, Market
from .detection import InsiderDetector, SuspicionReport
from .storage import Database
from .alerts.telegram import TelegramAlerter

# Initialize structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer() if not get_settings().log_json_format 
            else structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()
console = Console()


# =============================================================================
# Scanner Core
# =============================================================================

class CrystalBallScanner:
    """
    Main scanner that orchestrates the detection pipeline.
    
    Flow:
    1. Fetch recent trades from Polymarket
    2. For each trade:
       a. Get/create wallet profile
       b. Get market metadata
       c. Run detection signals
       d. If suspicious, save alert and notify
    3. Sleep and repeat
    
    The scanner maintains state to avoid re-processing trades
    and tracks metrics for monitoring.
    """
    
    def __init__(self):
        """Initialize the scanner with all dependencies."""
        self.settings = get_settings()
        
        # Components (initialized in start())
        self.client: Optional[PolymarketClient] = None
        self.db: Optional[Database] = None
        self.alerter: Optional[TelegramAlerter] = None
        self.detector = InsiderDetector()
        
        # State tracking
        self._processed_trade_ids: Set[str] = set()
        self._running = False
        self._last_scan_time: Optional[datetime] = None
        
        # Metrics
        self._scan_count = 0
        self._trades_processed = 0
        self._alerts_generated = 0
        self._alerts_sent = 0
        self._errors = 0
        
        # Market cache (avoid repeated API calls)
        self._market_cache: dict[str, Market] = {}
        self._market_cache_ttl = timedelta(minutes=5)
        self._market_cache_times: dict[str, datetime] = {}
    
    async def start(self) -> None:
        """Initialize all components and start scanning."""
        logger.info("scanner_starting")
        
        # Initialize components
        self.client = PolymarketClient()
        await self.client.__aenter__()
        
        self.db = Database()
        await self.db.initialize()
        
        self.alerter = TelegramAlerter()
        await self.alerter.__aenter__()
        
        # Send startup notification
        if self.alerter.is_configured:
            await self.alerter.send_startup_message()
        
        self._running = True
        logger.info("scanner_started")
    
    async def stop(self, reason: str = "Manual shutdown") -> None:
        """Gracefully shutdown all components."""
        logger.info("scanner_stopping", reason=reason)
        self._running = False
        
        # Send shutdown notification
        if self.alerter and self.alerter.is_configured:
            await self.alerter.send_shutdown_message(reason)
        
        # Close components
        if self.client:
            await self.client.__aexit__(None, None, None)
        if self.db:
            await self.db.close()
        if self.alerter:
            await self.alerter.__aexit__(None, None, None)
        
        logger.info("scanner_stopped")
    
    async def _get_market(self, market_id: str) -> Optional[Market]:
        """Get market with caching."""
        now = datetime.now(timezone.utc)
        
        # Check cache
        if market_id in self._market_cache:
            cache_time = self._market_cache_times.get(market_id)
            if cache_time and (now - cache_time) < self._market_cache_ttl:
                return self._market_cache[market_id]
        
        # Fetch from API
        market = await self.client.get_market(market_id)
        
        if market:
            self._market_cache[market_id] = market
            self._market_cache_times[market_id] = now
        
        return market
    
    def _should_skip_market(self, market: Market) -> bool:
        """Check if we should skip this market based on filters."""
        # Skip ignored markets
        if market.id in self.settings.ignored_markets:
            return True
        
        # Skip ignored events
        if market.event_slug and market.event_slug in self.settings.ignored_event_slugs:
            return True
        
        # Skip low volume markets
        if market.volume < self.settings.min_market_volume_usd:
            return True
        
        # Skip resolved markets
        if market.resolved:
            return True
        
        return False
    
    async def _process_trade(self, trade: Trade) -> Optional[SuspicionReport]:
        """
        Process a single trade through the detection pipeline.
        
        Returns a SuspicionReport if the trade is suspicious enough
        to alert on, None otherwise.
        """
        # Skip if already processed
        if trade.id in self._processed_trade_ids:
            return None
        
        self._processed_trade_ids.add(trade.id)
        self._trades_processed += 1
        
        # Get market metadata
        market = await self._get_market(trade.market)
        if not market:
            logger.debug("market_not_found", market_id=trade.market[:10])
            return None
        
        # Apply filters
        if self._should_skip_market(market):
            logger.debug("market_skipped", market_id=market.id[:10])
            return None
        
        # Get wallet profile
        wallet = await self.db.get_or_create_wallet(trade.maker)
        
        # Quick scan to avoid expensive analysis on obviously normal trades
        if not self.detector.quick_scan(wallet, trade, market):
            return None
        
        # Full analysis
        report = self.detector.analyze(
            wallet=wallet,
            trade=trade,
            market=market
        )
        
        # Update wallet stats
        await self.db.update_wallet_stats(trade.maker, trade.size_usd)
        
        # Check if we should alert
        if report.should_alert:
            self._alerts_generated += 1
            return report
        
        return None
    
    async def scan_once(self) -> list[SuspicionReport]:
        """
        Run a single scan cycle.
        
        Fetches recent trades and processes them through detection.
        Returns list of reports that triggered alerts.
        """
        self._scan_count += 1
        self._last_scan_time = datetime.now(timezone.utc)
        
        logger.debug("scan_starting", scan_number=self._scan_count)
        
        reports = []
        
        try:
            # Fetch recent trades
            trades = await self.client.get_recent_trades(limit=100)
            
            logger.debug("trades_fetched", count=len(trades))
            
            # Process each trade
            for trade in trades:
                try:
                    report = await self._process_trade(trade)
                    if report:
                        reports.append(report)
                        
                        # Save to database
                        await self.db.save_alert(report)
                        
                        # Send Telegram alert
                        if self.alerter.is_configured:
                            sent = await self.alerter.send_alert(report)
                            if sent:
                                self._alerts_sent += 1
                        
                        logger.info(
                            "alert_generated",
                            wallet=report.wallet_address[:10],
                            market=report.market.question[:30],
                            score=report.total_score
                        )
                        
                except Exception as e:
                    self._errors += 1
                    logger.error("trade_processing_error", error=str(e), trade_id=trade.id)
                    continue
            
        except Exception as e:
            self._errors += 1
            logger.error("scan_error", error=str(e))
            
            # Notify about errors (but not too frequently)
            if self.alerter and self.alerter.is_configured and self._errors % 10 == 1:
                await self.alerter.send_error(str(e), f"Scan #{self._scan_count}")
        
        logger.debug(
            "scan_complete",
            scan_number=self._scan_count,
            alerts=len(reports)
        )
        
        return reports
    
    async def run_forever(self) -> None:
        """
        Main loop - scan continuously until stopped.
        
        Uses the configured scan interval between cycles.
        """
        logger.info(
            "starting_continuous_scan",
            interval=self.settings.scan_interval_seconds
        )
        
        while self._running:
            try:
                await self.scan_once()
                
                # Clean up old processed IDs to prevent memory leak
                # Keep last 10000 trade IDs
                if len(self._processed_trade_ids) > 10000:
                    # Convert to list, keep recent half
                    ids_list = list(self._processed_trade_ids)
                    self._processed_trade_ids = set(ids_list[-5000:])
                
                # Wait for next scan
                await asyncio.sleep(self.settings.scan_interval_seconds)
                
            except asyncio.CancelledError:
                logger.info("scan_cancelled")
                break
            except Exception as e:
                logger.error("scan_loop_error", error=str(e))
                # Wait before retry
                await asyncio.sleep(10)
    
    def get_stats(self) -> dict:
        """Get current scanner statistics."""
        return {
            "scans": self._scan_count,
            "trades_processed": self._trades_processed,
            "alerts_generated": self._alerts_generated,
            "alerts_sent": self._alerts_sent,
            "errors": self._errors,
            "last_scan": self._last_scan_time.isoformat() if self._last_scan_time else None,
            "running": self._running
        }


# =============================================================================
# CLI Interface
# =============================================================================

def create_status_table(scanner: CrystalBallScanner) -> Table:
    """Create a rich table showing scanner status."""
    stats = scanner.get_stats()
    
    table = Table(title="🔮 Crystal Ball Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Status", "🟢 Running" if stats["running"] else "🔴 Stopped")
    table.add_row("Scans Completed", str(stats["scans"]))
    table.add_row("Trades Processed", f"{stats['trades_processed']:,}")
    table.add_row("Alerts Generated", str(stats["alerts_generated"]))
    table.add_row("Alerts Sent", str(stats["alerts_sent"]))
    table.add_row("Errors", str(stats["errors"]))
    
    if stats["last_scan"]:
        table.add_row("Last Scan", stats["last_scan"])
    
    return table


async def run_interactive(scanner: CrystalBallScanner) -> None:
    """Run scanner with interactive status display."""
    
    with Live(create_status_table(scanner), refresh_per_second=1) as live:
        while scanner._running:
            await scanner.scan_once()
            live.update(create_status_table(scanner))
            await asyncio.sleep(scanner.settings.scan_interval_seconds)


async def run_single_scan() -> None:
    """Run a single scan (useful for testing)."""
    scanner = CrystalBallScanner()
    
    try:
        await scanner.start()
        
        console.print("\n[bold yellow]Running single scan...[/bold yellow]\n")
        
        reports = await scanner.scan_once()
        
        if reports:
            console.print(f"\n[bold green]Found {len(reports)} suspicious trades![/bold green]\n")
            
            for report in reports:
                console.print(Panel(
                    f"Wallet: {report.wallet_address[:10]}...\n"
                    f"Market: {report.market.question[:50]}...\n"
                    f"Score: {report.total_score}/100\n"
                    f"Signals: {', '.join(s.signal_type.value for s in report.triggered_signals)}",
                    title=f"🚨 Alert (Score: {report.total_score})"
                ))
        else:
            console.print("\n[dim]No suspicious activity detected in this scan.[/dim]\n")
        
        # Show stats
        console.print(create_status_table(scanner))
        
    finally:
        await scanner.stop("Single scan complete")


async def run_continuous() -> None:
    """Run scanner continuously."""
    scanner = CrystalBallScanner()
    
    # Setup signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()
    
    def handle_signal(sig):
        logger.info("shutdown_signal_received", signal=sig.name)
        scanner._running = False
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: handle_signal(s))
    
    try:
        await scanner.start()
        
        console.print(Panel.fit(
            f"[bold green]Crystal Ball is now watching Polymarket[/bold green]\n\n"
            f"Scan interval: {scanner.settings.scan_interval_seconds}s\n"
            f"Alert threshold: {scanner.settings.detection.alert_threshold_score}/100\n"
            f"Telegram: {'✓ Configured' if scanner.alerter.is_configured else '✗ Not configured'}\n\n"
            f"Press Ctrl+C to stop",
            title="🔮 Witcher's Crystal Ball"
        ))
        
        await run_interactive(scanner)
        
    except asyncio.CancelledError:
        pass
    finally:
        await scanner.stop()
        
        # Final stats
        console.print("\n[bold]Final Statistics:[/bold]")
        console.print(create_status_table(scanner))


async def test_components() -> None:
    """Test all components are working."""
    console.print("\n[bold]Testing Components...[/bold]\n")
    
    settings = get_settings()
    
    # Test 1: Configuration
    console.print("[yellow]1. Configuration[/yellow]")
    console.print(f"   Scan interval: {settings.scan_interval_seconds}s")
    console.print(f"   Alert threshold: {settings.detection.alert_threshold_score}")
    console.print(f"   Database: {settings.database_path}")
    console.print("   [green]✓ Config loaded[/green]")
    
    # Test 2: Database
    console.print("\n[yellow]2. Database[/yellow]")
    try:
        db = Database()
        await db.initialize()
        await db.close()
        console.print("   [green]✓ Database initialized[/green]")
    except Exception as e:
        console.print(f"   [red]✗ Database error: {e}[/red]")
    
    # Test 3: Polymarket API
    console.print("\n[yellow]3. Polymarket API[/yellow]")
    try:
        async with PolymarketClient() as client:
            trades = await client.get_recent_trades(limit=5)
            console.print(f"   Fetched {len(trades)} trades")
            console.print("   [green]✓ API working[/green]")
    except Exception as e:
        console.print(f"   [red]✗ API error: {e}[/red]")
    
    # Test 4: Telegram
    console.print("\n[yellow]4. Telegram[/yellow]")
    alerter = TelegramAlerter()
    if alerter.is_configured:
        async with alerter:
            connected = await alerter.test_connection()
            if connected:
                console.print("   [green]✓ Telegram connected[/green]")
            else:
                console.print("   [red]✗ Telegram connection failed[/red]")
    else:
        console.print("   [dim]⊘ Not configured (optional)[/dim]")
    
    # Test 5: Detection
    console.print("\n[yellow]5. Detection Engine[/yellow]")
    detector = InsiderDetector()
    console.print(f"   Fresh wallet weight: {settings.detection.weight_fresh_wallet}")
    console.print(f"   Unusual sizing weight: {settings.detection.weight_unusual_sizing}")
    console.print("   [green]✓ Detector initialized[/green]")
    
    console.print("\n[bold green]All components ready![/bold green]\n")


def main():
    """Main entry point with argument handling."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Witcher's Crystal Ball - Polymarket Insider Detector"
    )
    parser.add_argument(
        "--single", "-s",
        action="store_true",
        help="Run a single scan and exit"
    )
    parser.add_argument(
        "--test", "-t",
        action="store_true",
        help="Test all components"
    )
    parser.add_argument(
        "--debug", "-d",
        action="store_true",
        help="Enable debug logging"
    )
    
    args = parser.parse_args()
    
    # Set log level
    if args.debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)
    
    # Run appropriate mode
    if args.test:
        asyncio.run(test_components())
    elif args.single:
        asyncio.run(run_single_scan())
    else:
        asyncio.run(run_continuous())


if __name__ == "__main__":
    main()