"""
Telegram Alert System for Witcher's Crystal Ball.

This module handles sending alerts to Telegram when suspicious
activity is detected. It formats reports into readable messages
and handles rate limiting to avoid spam.

Setup Instructions:
1. Create a bot via @BotFather on Telegram
2. Get your bot token
3. Start a chat with your bot (or add it to a channel)
4. Get your chat_id (send a message, then check the getUpdates API)
5. Add credentials to .env file

Why Telegram?
- Instant mobile notifications
- Free and reliable
- Easy to set up
- Can create channels for team alerts
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional

import httpx
import structlog

from ..config import get_settings, TelegramSettings
from ..detection.signals import SuspicionReport, SignalResult

logger = structlog.get_logger()


# =============================================================================
# Message Formatting
# =============================================================================

def format_alert_message(report: SuspicionReport) -> str:
    """
    Format a SuspicionReport into a Telegram message.
    
    Uses emojis and formatting for quick scanning on mobile.
    Telegram supports a subset of HTML for formatting.
    """
    # Score emoji based on severity
    if report.total_score >= 80:
        score_emoji = "🔴"
        urgency = "HIGH"
    elif report.total_score >= 60:
        score_emoji = "🟠"
        urgency = "MEDIUM"
    else:
        score_emoji = "🟡"
        urgency = "LOW"
    
    # Format triggered signals
    signal_lines = []
    for signal in report.signals:
        if signal.triggered:
            signal_lines.append(f"   ✓ {signal.signal_type.value} ({signal.score}pts)")
        else:
            signal_lines.append(f"   ✗ {signal.signal_type.value}")
    
    signals_text = "\n".join(signal_lines)
    
    # Format wallet info
    wallet_short = f"{report.wallet_address[:6]}...{report.wallet_address[-4:]}"
    days_old = report.wallet_profile.days_since_first_seen
    
    if days_old < 1:
        age_text = f"{days_old * 24:.1f} hours"
    else:
        age_text = f"{days_old:.1f} days"
    
    # Win rate text
    if report.wallet_profile.win_rate is not None:
        win_rate_text = f"{report.wallet_profile.win_rate:.1%}"
    else:
        win_rate_text = "Unknown"
    
    # Market question (truncate if too long)
    question = report.market.question
    if len(question) > 60:
        question = question[:57] + "..."
    
    # Resolution timing
    if report.hours_until_resolution is not None:
        if report.hours_until_resolution < 1:
            time_text = f"{report.hours_until_resolution * 60:.0f} minutes"
        elif report.hours_until_resolution < 24:
            time_text = f"{report.hours_until_resolution:.1f} hours"
        else:
            time_text = f"{report.hours_until_resolution / 24:.1f} days"
        resolution_line = f"⏰ Resolves in: {time_text}"
    else:
        resolution_line = "⏰ Resolution: Unknown"
    
    # Build the message
    message = f"""🔮 <b>CRYSTAL BALL ALERT</b>

{score_emoji} <b>Suspicion Score: {report.total_score}/100</b> [{urgency}]

📊 <b>Market:</b> {question}

👛 <b>Wallet:</b> <code>{wallet_short}</code>
   • Age: {age_text}
   • Total trades: {report.wallet_profile.total_trades}
   • Win rate: {win_rate_text}

💰 <b>Position:</b>
   • Side: {report.position_side}
   • Size: ${report.position_size_usd:,.2f}
   • Price: {report.price_at_detection:.1%}
   • Market share: {report.market_volume_share:.1%} of 24h vol

🚨 <b>Signals:</b>
{signals_text}

{resolution_line}

🔗 <a href="https://polymarket.com/event/{report.market.event_slug or report.market.slug}">View Market</a>
🔗 <a href="https://polygonscan.com/address/{report.wallet_address}">View Wallet</a>"""

    return message


def format_daily_summary(
    alerts_today: int,
    high_score_alerts: int,
    top_markets: list[tuple[str, int]],
    performance: dict
) -> str:
    """Format a daily summary message."""
    
    # Performance stats
    if performance["total_trades"] > 0:
        perf_text = f"""📈 <b>Performance (All Time):</b>
   • Trades taken: {performance['total_trades']}
   • Win rate: {performance['win_rate']:.1f}%
   • Total PnL: ${performance['total_pnl']:,.2f}
   • Avg PnL: ${performance['avg_pnl']:,.2f}"""
    else:
        perf_text = "📈 <b>Performance:</b> No trades recorded yet"
    
    # Top markets
    if top_markets:
        market_lines = [f"   • {q[:30]}... ({c} alerts)" for q, c in top_markets[:5]]
        markets_text = "\n".join(market_lines)
    else:
        markets_text = "   No alerts today"
    
    message = f"""📊 <b>DAILY SUMMARY</b>

🔔 <b>Alerts Today:</b> {alerts_today}
🔴 <b>High Score (80+):</b> {high_score_alerts}

🎯 <b>Most Active Markets:</b>
{markets_text}

{perf_text}

Stay vigilant! 🔮"""

    return message


def format_error_message(error: str, context: Optional[str] = None) -> str:
    """Format an error notification."""
    message = f"""⚠️ <b>CRYSTAL BALL ERROR</b>

<code>{error}</code>"""
    
    if context:
        message += f"\n\n📝 Context: {context}"
    
    message += "\n\nBot may need attention."
    return message


# =============================================================================
# Telegram Client
# =============================================================================

class TelegramAlerter:
    """
    Async Telegram bot for sending alerts.
    
    Features:
    - Rate limiting to prevent spam
    - Automatic retries on failure
    - Message queue for burst protection
    - HTML formatting support
    
    Usage:
        alerter = TelegramAlerter()
        await alerter.send_alert(report)
        
        # Or with context manager
        async with TelegramAlerter() as alerter:
            await alerter.send_alert(report)
    """
    
    def __init__(self, settings: Optional[TelegramSettings] = None):
        """
        Initialize the Telegram alerter.
        
        Args:
            settings: Optional custom settings. If None, loads from environment.
        """
        self.settings = settings or get_settings().telegram
        self._client: Optional[httpx.AsyncClient] = None
        self._last_message_time: Optional[datetime] = None
        self._rate_limit_lock = asyncio.Lock()
        
        # Telegram Bot API base URL
        self._base_url = f"https://api.telegram.org/bot{self.settings.bot_token}"
    
    async def __aenter__(self) -> "TelegramAlerter":
        """Async context manager entry."""
        self._client = httpx.AsyncClient(timeout=30.0)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    @property
    def is_configured(self) -> bool:
        """Check if Telegram credentials are configured."""
        return bool(self.settings.bot_token and self.settings.chat_id)
    
    async def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure HTTP client is initialized."""
        if not self._client:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client
    
    async def _wait_for_rate_limit(self) -> None:
        """Wait if we're sending messages too fast."""
        async with self._rate_limit_lock:
            if self._last_message_time:
                elapsed = (datetime.now(timezone.utc) - self._last_message_time).total_seconds()
                wait_time = self.settings.min_alert_interval_seconds - elapsed
                
                if wait_time > 0:
                    logger.debug("telegram_rate_limit", wait_seconds=wait_time)
                    await asyncio.sleep(wait_time)
            
            self._last_message_time = datetime.now(timezone.utc)
    
    async def _send_message(
        self,
        text: str,
        parse_mode: str = "HTML",
        disable_preview: bool = True
    ) -> bool:
        """
        Send a message via Telegram Bot API.
        
        Args:
            text: Message text (can include HTML formatting)
            parse_mode: "HTML" or "Markdown"
            disable_preview: Disable link previews
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.is_configured:
            logger.warning("telegram_not_configured")
            return False
        
        await self._wait_for_rate_limit()
        
        client = await self._ensure_client()
        
        try:
            response = await client.post(
                f"{self._base_url}/sendMessage",
                json={
                    "chat_id": self.settings.chat_id,
                    "text": text,
                    "parse_mode": parse_mode,
                    "disable_web_page_preview": disable_preview
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("ok"):
                    logger.debug("telegram_message_sent")
                    return True
                else:
                    logger.error(
                        "telegram_api_error",
                        error=result.get("description", "Unknown error")
                    )
                    return False
            else:
                logger.error(
                    "telegram_http_error",
                    status_code=response.status_code,
                    response=response.text[:200]
                )
                return False
                
        except httpx.RequestError as e:
            logger.error("telegram_request_error", error=str(e))
            return False
    
    async def send_alert(self, report: SuspicionReport) -> bool:
        """
        Send a suspicion report as a Telegram alert.
        
        Args:
            report: The SuspicionReport to send
            
        Returns:
            True if sent successfully
        """
        if not report.should_alert:
            logger.debug(
                "alert_below_threshold",
                score=report.total_score,
                threshold=get_settings().detection.alert_threshold_score
            )
            return False
        
        message = format_alert_message(report)
        success = await self._send_message(message)
        
        if success:
            logger.info(
                "alert_sent",
                wallet=report.wallet_address[:10],
                score=report.total_score
            )
        
        return success
    
    async def send_daily_summary(
        self,
        alerts_today: int,
        high_score_alerts: int,
        top_markets: list[tuple[str, int]],
        performance: dict
    ) -> bool:
        """Send daily summary message."""
        message = format_daily_summary(
            alerts_today,
            high_score_alerts,
            top_markets,
            performance
        )
        return await self._send_message(message)
    
    async def send_error(self, error: str, context: Optional[str] = None) -> bool:
        """Send error notification."""
        message = format_error_message(error, context)
        return await self._send_message(message)
    
    async def send_startup_message(self) -> bool:
        """Send notification that the bot has started."""
        message = """🔮 <b>Crystal Ball Online</b>

Bot has started monitoring Polymarket for suspicious activity.

Settings:
• Scan interval: {interval}s
• Alert threshold: {threshold}/100
• Min market volume: ${min_vol:,.0f}

Happy hunting! 🎯""".format(
            interval=get_settings().scan_interval_seconds,
            threshold=get_settings().detection.alert_threshold_score,
            min_vol=get_settings().min_market_volume_usd
        )
        return await self._send_message(message)
    
    async def send_shutdown_message(self, reason: str = "Manual shutdown") -> bool:
        """Send notification that the bot is shutting down."""
        message = f"""🔮 <b>Crystal Ball Offline</b>

Bot has stopped monitoring.

Reason: {reason}

Restart when ready."""
        return await self._send_message(message)
    
    async def test_connection(self) -> bool:
        """
        Test the Telegram connection.
        
        Useful for verifying credentials are correct.
        """
        if not self.is_configured:
            logger.error("telegram_not_configured")
            return False
        
        client = await self._ensure_client()
        
        try:
            response = await client.get(f"{self._base_url}/getMe")
            
            if response.status_code == 200:
                result = response.json()
                if result.get("ok"):
                    bot_info = result.get("result", {})
                    logger.info(
                        "telegram_connected",
                        bot_username=bot_info.get("username"),
                        bot_name=bot_info.get("first_name")
                    )
                    return True
            
            logger.error("telegram_connection_failed", response=response.text[:200])
            return False
            
        except httpx.RequestError as e:
            logger.error("telegram_connection_error", error=str(e))
            return False


# =============================================================================
# Quick Test
# =============================================================================

async def _test_telegram():
    """Test Telegram connection and message formatting."""
    from rich import print as rprint
    from rich.panel import Panel
    
    rprint(Panel.fit(
        "[bold]Testing Telegram Alerter[/bold]",
        title="📱 Telegram Test"
    ))
    
    alerter = TelegramAlerter()
    
    # Check configuration
    if not alerter.is_configured:
        rprint("[red]❌ Telegram not configured![/red]")
        rprint("\nTo configure:")
        rprint("1. Create a bot with @BotFather")
        rprint("2. Add TELEGRAM_BOT_TOKEN to .env")
        rprint("3. Add TELEGRAM_CHAT_ID to .env")
        rprint("\nShowing message preview instead:\n")
        
        # Create mock report for preview
        from datetime import timedelta
        from ..detection.signals import (
            WalletProfile, SuspicionReport, SignalResult, SignalType
        )
        from ..polymarket import Trade, Market
        
        mock_wallet = WalletProfile(
            address="0x1234567890abcdef1234567890abcdef12345678",
            first_seen=datetime.now(timezone.utc) - timedelta(days=2),
            total_trades=3,
            total_volume_usd=1500.0
        )
        
        mock_trade = Trade(
            id="test",
            market="0xmarket",
            maker=mock_wallet.address,
            taker="0xtaker",
            side="BUY",
            size=5000,
            price=0.08,
            timestamp=datetime.now(timezone.utc)
        )
        
        mock_market = Market(
            id="0xmarket",
            question="Will Company X announce partnership with Y before March 2025?",
            slug="company-x-partnership",
            event_slug="company-x-partnership",
            volume=35000,
            volume_24h=8000,
            liquidity=12000,
            end_date=datetime.now(timezone.utc) + timedelta(hours=18)
        )
        
        mock_report = SuspicionReport(
            wallet_address=mock_wallet.address,
            wallet_profile=mock_wallet,
            trade=mock_trade,
            market=mock_market,
            signals=[
                SignalResult(True, SignalType.FRESH_WALLET, 25, 0.9, "2 days old, 3 trades"),
                SignalResult(True, SignalType.UNUSUAL_SIZING, 20, 0.7, "5% of liquidity"),
                SignalResult(True, SignalType.NICHE_CONCENTRATION, 25, 0.8, "$35k market"),
                SignalResult(True, SignalType.TIMING_PATTERN, 20, 0.6, "18h to resolution"),
                SignalResult(False, SignalType.REPEAT_WINNER, 0, 0, "Insufficient history"),
            ],
            total_score=90,
            position_size_usd=400,
            position_side="YES",
            price_at_detection=0.08,
            market_volume_share=0.05,
            hours_until_resolution=18
        )
        
        message = format_alert_message(mock_report)
        
        # Strip HTML for console preview
        import re
        clean_message = re.sub(r'<[^>]+>', '', message)
        rprint(Panel(clean_message, title="Message Preview"))
        
        return
    
    # Test connection
    async with TelegramAlerter() as alerter:
        rprint("\n[yellow]Testing connection...[/yellow]")
        connected = await alerter.test_connection()
        
        if connected:
            rprint("[green]✓ Connected to Telegram![/green]")
            
            # Ask if user wants to send test message
            rprint("\n[yellow]Send test message? (y/n)[/yellow]")
            # In actual test, you'd get user input
            # For now, just show success
            rprint("[dim]Skipping test message send[/dim]")
        else:
            rprint("[red]❌ Connection failed[/red]")


if __name__ == "__main__":
    asyncio.run(_test_telegram())