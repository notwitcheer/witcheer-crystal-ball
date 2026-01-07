"""
Configuration management for Witcher's Crystal Ball.

Uses Pydantic Settings to load configuration from environment variables and .env files.
This approach gives us:
1. Type validation (catches config errors at startup, not runtime)
2. Default values with easy overrides
3. Automatic .env file loading
4. IDE autocomplete for all settings
"""

from pathlib import Path
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class DetectionSettings(BaseSettings):
    """
    Thresholds for insider detection signals.
    
    These are the core tuning parameters. Start with these defaults,
    then adjust based on your false positive/negative rate.
    """
    
    # Fresh Wallet Detection
    fresh_wallet_threshold_days: int = Field(
        default=7,
        description="Wallet is 'fresh' if first seen within this many days"
    )
    fresh_wallet_min_trades: int = Field(
        default=5,
        description="Wallet is 'fresh' if fewer than this many historical trades"
    )
    fresh_wallet_position_threshold_usd: float = Field(
        default=500.0,
        description="Minimum position size (USD) to flag a fresh wallet"
    )
    
    # Unusual Sizing Detection
    liquidity_threshold_pct: float = Field(
        default=0.05,
        description="Flag if position > this % of total market liquidity"
    )
    median_position_multiplier: float = Field(
        default=3.0,
        description="Flag if position > this multiple of median position size"
    )
    volume_threshold_pct: float = Field(
        default=0.10,
        description="Flag if single trade > this % of 24h volume"
    )
    
    # Niche Market Detection
    niche_market_volume_threshold_usd: float = Field(
        default=50000.0,
        description="Market is 'niche' if total volume below this"
    )
    position_dominance_threshold_pct: float = Field(
        default=0.20,
        description="Flag if wallet holds > this % of one side"
    )
    resolution_window_hours: int = Field(
        default=72,
        description="Only flag niche markets resolving within this window"
    )
    
    # Timing Pattern Detection
    last_minute_threshold_hours: int = Field(
        default=24,
        description="'Last minute' = position opened within this many hours of resolution"
    )
    coordination_time_window_minutes: int = Field(
        default=30,
        description="Window to detect coordinated wallet activity"
    )
    
    # Scoring
    alert_threshold_score: int = Field(
        default=60,
        description="Only alert if suspicion score >= this value (0-100)"
    )
    
    # Signal weights (must sum to 100 for clean scoring)
    weight_fresh_wallet: int = 25
    weight_unusual_sizing: int = 20
    weight_niche_concentration: int = 25
    weight_timing_pattern: int = 20
    weight_repeat_winner: int = 10


class TelegramSettings(BaseSettings):
    """Telegram bot configuration for sending alerts."""
    
    bot_token: str = Field(
        default="",
        description="Telegram bot token from @BotFather"
    )
    chat_id: str = Field(
        default="",
        description="Chat/channel ID to send alerts to"
    )
    
    # Optional: rate limiting to avoid spam
    min_alert_interval_seconds: int = Field(
        default=30,
        description="Minimum seconds between alerts (prevents spam)"
    )
    
    model_config = SettingsConfigDict(
        env_prefix="TELEGRAM_"  # Looks for TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
    )


class DashboardSettings(BaseSettings):
    """Web dashboard configuration."""

    # Server settings
    host: str = Field(
        default="127.0.0.1",
        description="Dashboard server host"
    )
    port: int = Field(
        default=8080,
        description="Dashboard server port"
    )

    # Security
    secret_key: str = Field(
        default="your-secret-key-change-this-in-production",
        description="Secret key for JWT signing and session encryption"
    )
    allowed_hosts: str = Field(
        default="127.0.0.1,localhost",
        description="Comma-separated list of allowed hosts"
    )
    cors_origins: str = Field(
        default="http://localhost:3000,http://127.0.0.1:3000",
        description="Comma-separated list of allowed CORS origins"
    )

    # Authentication
    access_token_expire_minutes: int = Field(
        default=30,
        description="JWT access token expiration time in minutes"
    )

    model_config = SettingsConfigDict(
        env_prefix="DASHBOARD_"
    )


class PolymarketSettings(BaseSettings):
    """Polymarket API configuration."""

    # Authentication (choose one)
    private_key: str = Field(
        default="",
        description="Polymarket wallet private key for authenticated API access"
    )
    api_key: str = Field(
        default="",
        description="Polymarket API key for basic API access"
    )
    chain_id: int = Field(
        default=137,
        description="Polygon chain ID (137 for mainnet, 80001 for testnet)"
    )

    # Base URLs
    clob_base_url: str = Field(
        default="https://clob.polymarket.com",
        description="CLOB API for trades, orders, positions"
    )
    gamma_base_url: str = Field(
        default="https://gamma-api.polymarket.com",
        description="Gamma API for markets, events metadata"
    )

    # Rate limiting (be nice to their servers)
    requests_per_second: float = Field(
        default=2.0,
        description="Max requests per second to avoid rate limits"
    )
    retry_max_attempts: int = Field(
        default=3,
        description="Max retry attempts on failed requests"
    )
    retry_base_delay_seconds: float = Field(
        default=1.0,
        description="Base delay for exponential backoff"
    )

    # Request timeout
    timeout_seconds: float = Field(
        default=30.0,
        description="HTTP request timeout"
    )

    model_config = SettingsConfigDict(
        env_prefix="POLYMARKET_"
    )


class Settings(BaseSettings):
    """
    Main application settings.
    
    Loads from environment variables and .env file.
    Environment variables take precedence over .env file.
    
    Usage:
        from config import get_settings
        settings = get_settings()
        print(settings.scan_interval_seconds)
    """
    
    # Monitoring behavior
    scan_interval_seconds: int = Field(
        default=60,
        description="How often to scan for new suspicious activity"
    )
    
    # Market filtering
    ignored_markets: list[str] = Field(
        default_factory=list,
        description="List of market IDs to ignore (e.g., too noisy)"
    )
    ignored_event_slugs: list[str] = Field(
        default_factory=list,
        description="Event slugs to ignore (e.g., 'presidential-election-2024')"
    )
    min_market_volume_usd: float = Field(
        default=1000.0,
        description="Ignore markets with less than this total volume"
    )
    
    # Database
    database_path: Path = Field(
        default=Path("data/crystal_ball.db"),
        description="SQLite database file path"
    )
    
    # Logging
    log_level: str = Field(
        default="INFO",
        description="Logging level: DEBUG, INFO, WARNING, ERROR"
    )
    log_json_format: bool = Field(
        default=False,
        description="Output logs as JSON (useful for log aggregation)"
    )
    
    # Nested settings
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    telegram: TelegramSettings = Field(default_factory=TelegramSettings)
    dashboard: DashboardSettings = Field(default_factory=DashboardSettings)
    polymarket: PolymarketSettings = Field(default_factory=PolymarketSettings)
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",  # Allows DETECTION__FRESH_WALLET_THRESHOLD_DAYS=14
        extra="ignore"  # Ignore unknown env vars
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Using lru_cache ensures we only load settings once,
    and the same instance is reused throughout the app.
    
    To reload settings (e.g., in tests), call:
        get_settings.cache_clear()
    """
    return Settings()


# Backwards compatibility aliases
Config = Settings
load_config = get_settings


# Quick validation when module is imported directly
if __name__ == "__main__":
    from rich import print as rprint
    from rich.panel import Panel
    
    settings = get_settings()
    
    rprint(Panel.fit(
        f"[green]✓ Configuration loaded successfully[/green]\n\n"
        f"Scan interval: {settings.scan_interval_seconds}s\n"
        f"Alert threshold: {settings.detection.alert_threshold_score}/100\n"
        f"Database: {settings.database_path}\n"
        f"Telegram configured: {bool(settings.telegram.bot_token)}",
        title="Witcher's Crystal Ball Config"
    ))