"""
Comprehensive configuration validation at application startup.

Validates all configuration settings, dependencies, and prerequisites
before the application starts to prevent runtime errors and security issues.
"""

import os
import asyncio
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
import structlog

from .config import get_settings
from .secure_config import get_secure_settings
from .exceptions import ConfigurationError, MissingConfigError, ValidationError
from .validation import WalletAddressValidator, MarketValidator
from .secure_logging import get_secure_logger
from .database_encryption import DatabaseEncryption

logger = get_secure_logger(__name__)


@dataclass
class ValidationResult:
    """Result of a configuration validation check."""
    check_name: str
    passed: bool
    level: str  # "critical", "warning", "info"
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    suggestions: List[str] = field(default_factory=list)


@dataclass
class ValidationSummary:
    """Summary of all validation results."""
    total_checks: int
    passed_checks: int
    failed_checks: int
    warnings: int
    critical_failures: int
    results: List[ValidationResult] = field(default_factory=list)
    is_valid: bool = False

    def add_result(self, result: ValidationResult):
        """Add a validation result."""
        self.results.append(result)
        self.total_checks += 1

        if result.passed:
            self.passed_checks += 1
        else:
            self.failed_checks += 1
            if result.level == "critical":
                self.critical_failures += 1
            elif result.level == "warning":
                self.warnings += 1

        # Update overall validity (no critical failures)
        self.is_valid = self.critical_failures == 0


class ConfigurationValidator:
    """
    Comprehensive configuration validator.

    Validates all aspects of application configuration including:
    - Required settings
    - Security configuration
    - Database setup
    - External service connectivity
    - File permissions and paths
    """

    def __init__(self):
        self.summary = ValidationSummary()
        self.settings = None
        self.secure_settings = None

    async def validate_all(self) -> ValidationSummary:
        """
        Run all configuration validations.

        Returns:
            ValidationSummary with all validation results
        """
        logger.info("configuration_validation_starting")

        try:
            # Load settings first
            await self._validate_settings_loading()

            # Run all validation checks
            validation_checks = [
                self._validate_basic_configuration,
                self._validate_security_configuration,
                self._validate_database_configuration,
                self._validate_api_configuration,
                self._validate_telegram_configuration,
                self._validate_detection_configuration,
                self._validate_file_permissions,
                self._validate_environment_setup,
                self._validate_dependencies,
            ]

            for check in validation_checks:
                try:
                    await check()
                except Exception as e:
                    self.summary.add_result(ValidationResult(
                        check_name=check.__name__,
                        passed=False,
                        level="critical",
                        message=f"Validation check failed: {e}",
                        details={"error": str(e)}
                    ))

            # Log summary
            self._log_validation_summary()

            return self.summary

        except Exception as e:
            logger.error("configuration_validation_failed", error=str(e))
            self.summary.add_result(ValidationResult(
                check_name="validation_framework",
                passed=False,
                level="critical",
                message=f"Configuration validation framework failed: {e}"
            ))
            return self.summary

    async def _validate_settings_loading(self):
        """Validate that settings can be loaded."""
        try:
            self.settings = get_settings()
            self.summary.add_result(ValidationResult(
                check_name="settings_loading",
                passed=True,
                level="info",
                message="Base settings loaded successfully"
            ))
        except Exception as e:
            self.summary.add_result(ValidationResult(
                check_name="settings_loading",
                passed=False,
                level="critical",
                message=f"Failed to load base settings: {e}",
                suggestions=["Check .env file format", "Verify environment variables"]
            ))
            raise

        try:
            self.secure_settings = await get_secure_settings()
            self.summary.add_result(ValidationResult(
                check_name="secure_settings_loading",
                passed=True,
                level="info",
                message="Secure settings loaded successfully"
            ))
        except Exception as e:
            self.summary.add_result(ValidationResult(
                check_name="secure_settings_loading",
                passed=False,
                level="warning",
                message=f"Failed to load secure settings: {e}",
                suggestions=["Set SECRETS_PASSWORD environment variable", "Run secrets migration"]
            ))

    async def _validate_basic_configuration(self):
        """Validate basic configuration settings."""
        # Check scan interval
        if self.settings.scan_interval_seconds < 10:
            self.summary.add_result(ValidationResult(
                check_name="scan_interval",
                passed=False,
                level="warning",
                message=f"Scan interval very low: {self.settings.scan_interval_seconds}s",
                suggestions=["Consider increasing to reduce API load"]
            ))
        elif self.settings.scan_interval_seconds > 300:
            self.summary.add_result(ValidationResult(
                check_name="scan_interval",
                passed=False,
                level="warning",
                message=f"Scan interval very high: {self.settings.scan_interval_seconds}s",
                suggestions=["Consider decreasing for faster detection"]
            ))
        else:
            self.summary.add_result(ValidationResult(
                check_name="scan_interval",
                passed=True,
                level="info",
                message=f"Scan interval acceptable: {self.settings.scan_interval_seconds}s"
            ))

        # Check minimum volume threshold
        if self.settings.min_market_volume_usd < 100:
            self.summary.add_result(ValidationResult(
                check_name="min_market_volume",
                passed=False,
                level="warning",
                message="Minimum market volume very low - may generate many alerts",
                suggestions=["Consider increasing to filter small markets"]
            ))
        else:
            self.summary.add_result(ValidationResult(
                check_name="min_market_volume",
                passed=True,
                level="info",
                message=f"Minimum market volume: ${self.settings.min_market_volume_usd:,.2f}"
            ))

        # Validate log level
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.settings.log_level.upper() not in valid_levels:
            self.summary.add_result(ValidationResult(
                check_name="log_level",
                passed=False,
                level="critical",
                message=f"Invalid log level: {self.settings.log_level}",
                suggestions=[f"Use one of: {', '.join(valid_levels)}"]
            ))
        else:
            self.summary.add_result(ValidationResult(
                check_name="log_level",
                passed=True,
                level="info",
                message=f"Log level: {self.settings.log_level}"
            ))

    async def _validate_security_configuration(self):
        """Validate security-related configuration."""
        # Check if secrets management is properly configured
        if self.secure_settings:
            status = self.secure_settings.get_secrets_status()

            if status["is_secure"]:
                self.summary.add_result(ValidationResult(
                    check_name="secrets_management",
                    passed=True,
                    level="info",
                    message="Secure secrets management enabled"
                ))
            else:
                self.summary.add_result(ValidationResult(
                    check_name="secrets_management",
                    passed=False,
                    level="warning",
                    message="Using insecure environment variable storage for secrets",
                    suggestions=["Set SECRETS_PASSWORD to enable encryption", "Run secrets migration"]
                ))

        # Check database encryption
        db_encryption_password = os.getenv("DB_ENCRYPTION_PASSWORD")
        if db_encryption_password:
            if len(db_encryption_password) < 12:
                self.summary.add_result(ValidationResult(
                    check_name="db_encryption_password",
                    passed=False,
                    level="critical",
                    message="Database encryption password too short",
                    suggestions=["Use at least 12 characters for database encryption password"]
                ))
            else:
                self.summary.add_result(ValidationResult(
                    check_name="db_encryption_password",
                    passed=True,
                    level="info",
                    message="Database encryption configured"
                ))
        else:
            self.summary.add_result(ValidationResult(
                check_name="db_encryption_password",
                passed=False,
                level="warning",
                message="Database encryption not configured",
                suggestions=["Set DB_ENCRYPTION_PASSWORD for encrypted storage"]
            ))

        # Validate detection signal weights
        weights = [
            self.settings.detection.weight_fresh_wallet,
            self.settings.detection.weight_unusual_sizing,
            self.settings.detection.weight_niche_concentration,
            self.settings.detection.weight_timing_pattern,
            self.settings.detection.weight_repeat_winner
        ]

        total_weight = sum(weights)
        if abs(total_weight - 100) > 1:  # Allow 1% tolerance
            self.summary.add_result(ValidationResult(
                check_name="detection_weights",
                passed=False,
                level="warning",
                message=f"Detection weights sum to {total_weight}% (should be 100%)",
                suggestions=["Adjust detection signal weights to sum to 100"]
            ))
        else:
            self.summary.add_result(ValidationResult(
                check_name="detection_weights",
                passed=True,
                level="info",
                message="Detection weights properly configured"
            ))

    async def _validate_database_configuration(self):
        """Validate database configuration."""
        # Check database path
        db_path = self.settings.database_path

        # Check if parent directory exists or can be created
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self.summary.add_result(ValidationResult(
                check_name="database_directory",
                passed=True,
                level="info",
                message=f"Database directory accessible: {db_path.parent}"
            ))
        except Exception as e:
            self.summary.add_result(ValidationResult(
                check_name="database_directory",
                passed=False,
                level="critical",
                message=f"Cannot create database directory: {e}",
                suggestions=["Check file permissions", "Verify disk space"]
            ))

        # Check if database file exists and permissions
        if db_path.exists():
            if db_path.is_file():
                try:
                    # Test write access
                    with open(db_path, 'a'):
                        pass
                    self.summary.add_result(ValidationResult(
                        check_name="database_permissions",
                        passed=True,
                        level="info",
                        message="Database file is writable"
                    ))
                except Exception as e:
                    self.summary.add_result(ValidationResult(
                        check_name="database_permissions",
                        passed=False,
                        level="critical",
                        message=f"Database file not writable: {e}",
                        suggestions=["Check file permissions"]
                    ))
            else:
                self.summary.add_result(ValidationResult(
                    check_name="database_file",
                    passed=False,
                    level="critical",
                    message=f"Database path exists but is not a file: {db_path}",
                    suggestions=["Remove conflicting directory or file"]
                ))
        else:
            self.summary.add_result(ValidationResult(
                check_name="database_file",
                passed=True,
                level="info",
                message="Database will be created on first run"
            ))

    async def _validate_api_configuration(self):
        """Validate API configuration."""
        # Check Polymarket configuration
        if self.secure_settings:
            try:
                private_key = await self.secure_settings.get_polymarket_private_key()
                if private_key:
                    # Validate private key format
                    if re.match(r'^0x[a-fA-F0-9]{64}$', private_key):
                        self.summary.add_result(ValidationResult(
                            check_name="polymarket_private_key",
                            passed=True,
                            level="info",
                            message="Polymarket private key format valid"
                        ))
                    else:
                        self.summary.add_result(ValidationResult(
                            check_name="polymarket_private_key",
                            passed=False,
                            level="critical",
                            message="Invalid Polymarket private key format",
                            suggestions=["Private key should be 0x followed by 64 hex characters"]
                        ))
                else:
                    self.summary.add_result(ValidationResult(
                        check_name="polymarket_private_key",
                        passed=False,
                        level="critical",
                        message="Polymarket private key not configured",
                        suggestions=["Set POLYMARKET_PRIVATE_KEY or migrate to secure storage"]
                    ))
            except Exception as e:
                self.summary.add_result(ValidationResult(
                    check_name="polymarket_private_key",
                    passed=False,
                    level="critical",
                    message=f"Failed to retrieve Polymarket private key: {e}"
                ))

        # Validate API URLs
        urls_to_check = [
            ("polymarket_clob_url", self.settings.polymarket.clob_base_url),
            ("polymarket_gamma_url", self.settings.polymarket.gamma_base_url)
        ]

        for name, url in urls_to_check:
            if url.startswith(('http://', 'https://')):
                self.summary.add_result(ValidationResult(
                    check_name=name,
                    passed=True,
                    level="info",
                    message=f"Valid URL format: {url}"
                ))
            else:
                self.summary.add_result(ValidationResult(
                    check_name=name,
                    passed=False,
                    level="critical",
                    message=f"Invalid URL format: {url}",
                    suggestions=["URL must start with http:// or https://"]
                ))

        # Check rate limiting configuration
        if self.settings.polymarket.requests_per_second <= 0:
            self.summary.add_result(ValidationResult(
                check_name="polymarket_rate_limit",
                passed=False,
                level="critical",
                message="Invalid rate limit configuration",
                suggestions=["requests_per_second must be > 0"]
            ))
        elif self.settings.polymarket.requests_per_second > 10:
            self.summary.add_result(ValidationResult(
                check_name="polymarket_rate_limit",
                passed=False,
                level="warning",
                message="Very high rate limit may cause API blocking",
                suggestions=["Consider reducing requests_per_second"]
            ))
        else:
            self.summary.add_result(ValidationResult(
                check_name="polymarket_rate_limit",
                passed=True,
                level="info",
                message=f"Rate limit: {self.settings.polymarket.requests_per_second} req/s"
            ))

    async def _validate_telegram_configuration(self):
        """Validate Telegram configuration."""
        if self.secure_settings:
            try:
                bot_token = await self.secure_settings.get_telegram_bot_token()
                chat_id = await self.secure_settings.get_telegram_chat_id()

                if bot_token and chat_id:
                    # Validate bot token format
                    if re.match(r'^\d+:[A-Za-z0-9_-]{35}$', bot_token):
                        self.summary.add_result(ValidationResult(
                            check_name="telegram_bot_token",
                            passed=True,
                            level="info",
                            message="Telegram bot token format valid"
                        ))
                    else:
                        self.summary.add_result(ValidationResult(
                            check_name="telegram_bot_token",
                            passed=False,
                            level="warning",
                            message="Invalid Telegram bot token format",
                            suggestions=["Get token from @BotFather"]
                        ))

                    # Validate chat ID format
                    if re.match(r'^-?\d+$', chat_id):
                        self.summary.add_result(ValidationResult(
                            check_name="telegram_chat_id",
                            passed=True,
                            level="info",
                            message="Telegram chat ID format valid"
                        ))
                    else:
                        self.summary.add_result(ValidationResult(
                            check_name="telegram_chat_id",
                            passed=False,
                            level="warning",
                            message="Invalid Telegram chat ID format",
                            suggestions=["Chat ID should be numeric"]
                        ))
                else:
                    self.summary.add_result(ValidationResult(
                        check_name="telegram_configuration",
                        passed=False,
                        level="warning",
                        message="Telegram not configured - alerts will be logged only",
                        suggestions=["Configure TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID for alerts"]
                    ))

                # Check alert interval
                if self.settings.telegram.min_alert_interval_seconds < 10:
                    self.summary.add_result(ValidationResult(
                        check_name="telegram_alert_interval",
                        passed=False,
                        level="warning",
                        message="Very short alert interval may spam Telegram",
                        suggestions=["Consider increasing min_alert_interval_seconds"]
                    ))

            except Exception as e:
                self.summary.add_result(ValidationResult(
                    check_name="telegram_configuration",
                    passed=False,
                    level="warning",
                    message=f"Failed to validate Telegram configuration: {e}"
                ))

    async def _validate_detection_configuration(self):
        """Validate detection signal configuration."""
        detection = self.settings.detection

        # Check thresholds are reasonable
        thresholds_to_check = [
            ("fresh_wallet_threshold_days", detection.fresh_wallet_threshold_days, 1, 30),
            ("fresh_wallet_min_trades", detection.fresh_wallet_min_trades, 1, 100),
            ("alert_threshold_score", detection.alert_threshold_score, 1, 100),
            ("liquidity_threshold_pct", detection.liquidity_threshold_pct, 0.001, 0.5),
            ("volume_threshold_pct", detection.volume_threshold_pct, 0.001, 1.0),
        ]

        for name, value, min_val, max_val in thresholds_to_check:
            if not (min_val <= value <= max_val):
                self.summary.add_result(ValidationResult(
                    check_name=f"detection_{name}",
                    passed=False,
                    level="warning",
                    message=f"{name} value {value} outside recommended range [{min_val}, {max_val}]",
                    suggestions=[f"Consider adjusting {name} to reasonable range"]
                ))
            else:
                self.summary.add_result(ValidationResult(
                    check_name=f"detection_{name}",
                    passed=True,
                    level="info",
                    message=f"{name}: {value}"
                ))

    async def _validate_file_permissions(self):
        """Validate file and directory permissions."""
        # Check data directory
        data_dir = Path("data")
        try:
            data_dir.mkdir(exist_ok=True)
            # Test write access
            test_file = data_dir / "test_permissions.tmp"
            test_file.write_text("test")
            test_file.unlink()

            self.summary.add_result(ValidationResult(
                check_name="data_directory_permissions",
                passed=True,
                level="info",
                message="Data directory is writable"
            ))
        except Exception as e:
            self.summary.add_result(ValidationResult(
                check_name="data_directory_permissions",
                passed=False,
                level="critical",
                message=f"Cannot write to data directory: {e}",
                suggestions=["Check file permissions", "Create data directory manually"]
            ))

        # Check .env file permissions if it exists
        env_file = Path(".env")
        if env_file.exists():
            stat = env_file.stat()
            # Check if readable by others (potential security issue)
            if stat.st_mode & 0o044:  # Others can read
                self.summary.add_result(ValidationResult(
                    check_name="env_file_permissions",
                    passed=False,
                    level="warning",
                    message=".env file is readable by others",
                    suggestions=["Run: chmod 600 .env"]
                ))
            else:
                self.summary.add_result(ValidationResult(
                    check_name="env_file_permissions",
                    passed=True,
                    level="info",
                    message=".env file has secure permissions"
                ))

    async def _validate_environment_setup(self):
        """Validate environment setup."""
        # Check Python version
        import sys
        python_version = sys.version_info

        if python_version < (3, 11):
            self.summary.add_result(ValidationResult(
                check_name="python_version",
                passed=False,
                level="critical",
                message=f"Python {python_version.major}.{python_version.minor} too old",
                suggestions=["Upgrade to Python 3.11 or newer"]
            ))
        else:
            self.summary.add_result(ValidationResult(
                check_name="python_version",
                passed=True,
                level="info",
                message=f"Python {python_version.major}.{python_version.minor}.{python_version.micro}"
            ))

        # Check required environment variables
        required_for_production = [
            "SECRETS_PASSWORD",
            "DB_ENCRYPTION_PASSWORD"
        ]

        for env_var in required_for_production:
            if os.getenv(env_var):
                self.summary.add_result(ValidationResult(
                    check_name=f"env_var_{env_var}",
                    passed=True,
                    level="info",
                    message=f"{env_var} is set"
                ))
            else:
                self.summary.add_result(ValidationResult(
                    check_name=f"env_var_{env_var}",
                    passed=False,
                    level="warning",
                    message=f"{env_var} not set",
                    suggestions=[f"Set {env_var} for production deployment"]
                ))

    async def _validate_dependencies(self):
        """Validate required dependencies."""
        required_packages = [
            "aiosqlite",
            "httpx",
            "pydantic",
            "structlog",
            "cryptography",
            "py-clob-client"
        ]

        for package in required_packages:
            try:
                __import__(package.replace("-", "_"))
                self.summary.add_result(ValidationResult(
                    check_name=f"dependency_{package}",
                    passed=True,
                    level="info",
                    message=f"{package} available"
                ))
            except ImportError:
                self.summary.add_result(ValidationResult(
                    check_name=f"dependency_{package}",
                    passed=False,
                    level="critical",
                    message=f"Required package {package} not found",
                    suggestions=[f"Install with: pip install {package}"]
                ))

    def _log_validation_summary(self):
        """Log validation summary."""
        if self.summary.is_valid:
            logger.info("configuration_validation_passed",
                       total_checks=self.summary.total_checks,
                       passed=self.summary.passed_checks,
                       warnings=self.summary.warnings)
        else:
            logger.error("configuration_validation_failed",
                        total_checks=self.summary.total_checks,
                        passed=self.summary.passed_checks,
                        failed=self.summary.failed_checks,
                        critical_failures=self.summary.critical_failures)

        # Log individual critical failures
        for result in self.summary.results:
            if result.level == "critical" and not result.passed:
                logger.critical("critical_config_error",
                              check=result.check_name,
                              message=result.message,
                              suggestions=result.suggestions)


async def validate_configuration() -> ValidationSummary:
    """
    Main entry point for configuration validation.

    Returns:
        ValidationSummary with all validation results
    """
    validator = ConfigurationValidator()
    return await validator.validate_all()


def print_validation_report(summary: ValidationSummary) -> None:
    """Print a human-readable validation report."""
    print("\n" + "=" * 60)
    print("🔧 CONFIGURATION VALIDATION REPORT")
    print("=" * 60)

    print(f"\n📊 Summary:")
    print(f"  Total checks: {summary.total_checks}")
    print(f"  ✅ Passed: {summary.passed_checks}")
    print(f"  ❌ Failed: {summary.failed_checks}")
    print(f"  ⚠️ Warnings: {summary.warnings}")
    print(f"  🚨 Critical: {summary.critical_failures}")

    if summary.is_valid:
        print(f"\n✅ Overall status: VALID")
    else:
        print(f"\n❌ Overall status: INVALID ({summary.critical_failures} critical issues)")

    # Group results by level
    critical_results = [r for r in summary.results if r.level == "critical" and not r.passed]
    warning_results = [r for r in summary.results if r.level == "warning" and not r.passed]

    if critical_results:
        print(f"\n🚨 Critical Issues:")
        for result in critical_results:
            print(f"  ❌ {result.check_name}: {result.message}")
            for suggestion in result.suggestions:
                print(f"     💡 {suggestion}")

    if warning_results:
        print(f"\n⚠️ Warnings:")
        for result in warning_results:
            print(f"  ⚠️ {result.check_name}: {result.message}")
            for suggestion in result.suggestions:
                print(f"     💡 {suggestion}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    async def main():
        summary = await validate_configuration()
        print_validation_report(summary)

    asyncio.run(main())