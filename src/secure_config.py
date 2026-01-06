"""
Secure configuration helper that integrates secrets management.

This module extends the base configuration with secure secrets handling,
ensuring sensitive data is not stored in plain text .env files.
"""

import asyncio
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import structlog

from .config import Settings, get_settings
from .secrets_manager import (
    get_secrets_manager,
    get_polymarket_private_key,
    get_telegram_bot_token,
    migrate_secrets_from_env
)
from .exceptions import ConfigurationError, MissingConfigError

logger = structlog.get_logger(__name__)


class SecureSettings:
    """
    Secure wrapper for application settings that uses secrets manager.

    This class provides the same interface as Settings but automatically
    retrieves sensitive data from secure storage instead of .env files.
    """

    def __init__(self, base_settings: Optional[Settings] = None):
        self._base_settings = base_settings or get_settings()
        self._secrets_manager = get_secrets_manager()
        self._cached_secrets = {}

    async def get_polymarket_private_key(self) -> str:
        """Get Polymarket private key from secure storage."""
        if "polymarket_private_key" not in self._cached_secrets:
            try:
                private_key = await get_polymarket_private_key()
                self._cached_secrets["polymarket_private_key"] = private_key
                logger.debug("polymarket_private_key_retrieved")
            except Exception as e:
                logger.error("failed_to_retrieve_polymarket_private_key", error=str(e))
                raise

        return self._cached_secrets["polymarket_private_key"]

    async def get_telegram_bot_token(self) -> str:
        """Get Telegram bot token from secure storage."""
        if "telegram_bot_token" not in self._cached_secrets:
            try:
                token = await get_telegram_bot_token()
                self._cached_secrets["telegram_bot_token"] = token
                logger.debug("telegram_bot_token_retrieved")
            except Exception as e:
                logger.error("failed_to_retrieve_telegram_bot_token", error=str(e))
                # Don't fail if Telegram is not configured
                return ""

        return self._cached_secrets["telegram_bot_token"]

    async def get_telegram_chat_id(self) -> str:
        """Get Telegram chat ID from secure storage or base config."""
        if "telegram_chat_id" not in self._cached_secrets:
            # Try secure storage first
            chat_id = await self._secrets_manager.get_secret("telegram_chat_id")

            # Fallback to base config
            if not chat_id:
                chat_id = self._base_settings.telegram.chat_id

            self._cached_secrets["telegram_chat_id"] = chat_id or ""

        return self._cached_secrets["telegram_chat_id"]

    def clear_cache(self):
        """Clear cached secrets (forces re-fetch from storage)."""
        self._cached_secrets.clear()
        logger.debug("secrets_cache_cleared")

    # Proxy all other settings through base_settings
    @property
    def scan_interval_seconds(self) -> int:
        return self._base_settings.scan_interval_seconds

    @property
    def ignored_markets(self) -> list[str]:
        return self._base_settings.ignored_markets

    @property
    def ignored_event_slugs(self) -> list[str]:
        return self._base_settings.ignored_event_slugs

    @property
    def min_market_volume_usd(self) -> float:
        return self._base_settings.min_market_volume_usd

    @property
    def database_path(self):
        return self._base_settings.database_path

    @property
    def log_level(self) -> str:
        return self._base_settings.log_level

    @property
    def log_json_format(self) -> bool:
        return self._base_settings.log_json_format

    @property
    def detection(self):
        return self._base_settings.detection

    @property
    def polymarket(self):
        return self._base_settings.polymarket

    @property
    def telegram(self):
        return self._base_settings.telegram

    def get_secrets_status(self) -> dict:
        """Get status of secrets management."""
        return {
            "secrets_backend": self._secrets_manager.get_backend_info(),
            "cached_secrets": list(self._cached_secrets.keys()),
            "is_secure": not self._secrets_manager.get_backend_info()["active_backend"] == "EnvironmentSecretsBackend"
        }


# Global secure settings instance
_secure_settings: Optional[SecureSettings] = None


async def get_secure_settings() -> SecureSettings:
    """Get or create secure settings instance."""
    global _secure_settings
    if _secure_settings is None:
        _secure_settings = SecureSettings()
    return _secure_settings


async def initialize_secure_configuration() -> SecureSettings:
    """
    Initialize secure configuration system.

    This function should be called at application startup to:
    1. Setup secrets management
    2. Check for required secrets
    3. Migrate from .env if needed

    Returns:
        Configured SecureSettings instance
    """
    logger.info("initializing_secure_configuration")

    try:
        # Get secure settings instance
        settings = await get_secure_settings()

        # Check secrets status
        status = settings.get_secrets_status()
        logger.info("secrets_status", **status)

        # If using environment backend, warn about security
        if not status["is_secure"]:
            logger.warning(
                "using_insecure_secrets_backend",
                backend=status["secrets_backend"]["active_backend"],
                recommendation="Set SECRETS_PASSWORD environment variable to enable encrypted storage"
            )

        # Verify essential secrets are available
        await _verify_essential_secrets(settings)

        logger.info("secure_configuration_initialized")
        return settings

    except Exception as e:
        logger.error("failed_to_initialize_secure_configuration", error=str(e))
        raise ConfigurationError(
            "secure_configuration",
            f"Failed to initialize secure configuration: {e}"
        )


async def _verify_essential_secrets(settings: SecureSettings) -> None:
    """Verify that essential secrets are available."""
    secrets_status = {}

    # Check Polymarket private key
    try:
        private_key = await settings.get_polymarket_private_key()
        secrets_status["polymarket_private_key"] = "✅ Available"
        logger.debug("polymarket_private_key_verified")
    except MissingConfigError:
        secrets_status["polymarket_private_key"] = "❌ Missing"
        logger.error("polymarket_private_key_missing")
        raise
    except Exception as e:
        secrets_status["polymarket_private_key"] = f"❌ Error: {e}"
        logger.error("polymarket_private_key_error", error=str(e))
        raise

    # Check Telegram config (optional)
    try:
        token = await settings.get_telegram_bot_token()
        chat_id = await settings.get_telegram_chat_id()
        if token and chat_id:
            secrets_status["telegram"] = "✅ Available"
        else:
            secrets_status["telegram"] = "⚠️ Partially configured"
    except Exception as e:
        secrets_status["telegram"] = f"❌ Error: {e}"
        logger.warning("telegram_config_error", error=str(e))

    logger.info("secrets_verification_complete", **secrets_status)


async def migrate_to_secure_storage() -> None:
    """
    Migrate secrets from .env file to secure storage.

    This is a one-time operation to move from insecure .env storage
    to encrypted storage. Should be run manually after setting up
    a secrets password.
    """
    logger.info("starting_secrets_migration")

    try:
        await migrate_secrets_from_env()
        logger.info("secrets_migration_completed")

        # Clear any cached settings to force reload
        global _secure_settings
        if _secure_settings:
            _secure_settings.clear_cache()

        logger.info(
            "migration_recommendation",
            message="Consider removing secrets from .env file and regenerating keys for maximum security"
        )

    except Exception as e:
        logger.error("secrets_migration_failed", error=str(e))
        raise ConfigurationError(
            "secrets_migration",
            f"Failed to migrate secrets: {e}"
        )


# Convenience function for CLI usage
def setup_secrets_cli():
    """Command line interface for setting up secure secrets."""
    import getpass

    print("🔒 Witcher's Crystal Ball - Secure Secrets Setup")
    print()

    # Get password for encryption
    password = getpass.getpass("Enter password for secrets encryption: ")
    confirm_password = getpass.getpass("Confirm password: ")

    if password != confirm_password:
        print("❌ Passwords don't match!")
        return False

    if len(password) < 8:
        print("❌ Password must be at least 8 characters!")
        return False

    # Setup encrypted storage
    import os
    os.environ["SECRETS_PASSWORD"] = password

    print("✅ Password set. Running migration...")

    # Run async migration
    try:
        asyncio.run(migrate_to_secure_storage())
        print("✅ Secrets migration completed!")
        print()
        print("Next steps:")
        print("1. Set SECRETS_PASSWORD environment variable in your shell")
        print("2. Remove sensitive data from .env file")
        print("3. Restart the application")
        return True
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False


if __name__ == "__main__":
    setup_secrets_cli()