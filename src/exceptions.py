"""
Specific exception classes for Witcher's Crystal Ball.

Provides detailed error types for different failure scenarios,
enabling better error handling and debugging.
"""

from typing import Any, Dict, Optional


class CrystalBallError(Exception):
    """Base exception for all Crystal Ball errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} - Details: {self.details}"
        return self.message


# =============================================================================
# API Related Errors
# =============================================================================

class APIError(CrystalBallError):
    """Base class for API-related errors."""
    pass


class PolymarketAPIError(APIError):
    """Polymarket API specific errors."""

    def __init__(self, message: str, status_code: Optional[int] = None,
                 endpoint: Optional[str] = None, response_data: Optional[Dict] = None):
        self.status_code = status_code
        self.endpoint = endpoint
        self.response_data = response_data

        details = {}
        if status_code:
            details['status_code'] = status_code
        if endpoint:
            details['endpoint'] = endpoint
        if response_data:
            details['response_data'] = response_data

        super().__init__(message, details)


class APIAuthenticationError(PolymarketAPIError):
    """Authentication failed with Polymarket API."""
    pass


class APIRateLimitError(PolymarketAPIError):
    """API rate limit exceeded."""

    def __init__(self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None,
                 endpoint: Optional[str] = None):
        self.retry_after = retry_after

        details = {'retry_after': retry_after} if retry_after else {}
        super().__init__(message, status_code=429, endpoint=endpoint,
                         response_data=details)


class APITimeoutError(PolymarketAPIError):
    """API request timed out."""

    def __init__(self, message: str = "Request timed out", timeout_seconds: Optional[float] = None,
                 endpoint: Optional[str] = None):
        self.timeout_seconds = timeout_seconds

        details = {'timeout_seconds': timeout_seconds} if timeout_seconds else {}
        super().__init__(message, status_code=408, endpoint=endpoint,
                         response_data=details)


class APIConnectionError(PolymarketAPIError):
    """Failed to connect to API."""
    pass


class APIServerError(PolymarketAPIError):
    """Server error from API (5xx)."""
    pass


class APIClientError(PolymarketAPIError):
    """Client error from API (4xx)."""
    pass


class APIDataError(APIError):
    """Invalid or corrupted data from API."""

    def __init__(self, message: str, data: Optional[Any] = None,
                 validation_errors: Optional[Dict] = None):
        self.data = data
        self.validation_errors = validation_errors

        details = {}
        if data is not None:
            details['data'] = data
        if validation_errors:
            details['validation_errors'] = validation_errors

        super().__init__(message, details)


# =============================================================================
# Database Related Errors
# =============================================================================

class DatabaseError(CrystalBallError):
    """Base class for database-related errors."""
    pass


class DatabaseConnectionError(DatabaseError):
    """Failed to connect to database."""
    pass


class DatabaseMigrationError(DatabaseError):
    """Database migration failed."""

    def __init__(self, message: str, migration_name: Optional[str] = None,
                 sql_error: Optional[str] = None):
        self.migration_name = migration_name
        self.sql_error = sql_error

        details = {}
        if migration_name:
            details['migration_name'] = migration_name
        if sql_error:
            details['sql_error'] = sql_error

        super().__init__(message, details)


class DatabaseIntegrityError(DatabaseError):
    """Database integrity constraint violation."""

    def __init__(self, message: str, constraint: Optional[str] = None,
                 table: Optional[str] = None):
        self.constraint = constraint
        self.table = table

        details = {}
        if constraint:
            details['constraint'] = constraint
        if table:
            details['table'] = table

        super().__init__(message, details)


class WalletNotFoundError(DatabaseError):
    """Requested wallet not found in database."""

    def __init__(self, wallet_address: str):
        self.wallet_address = wallet_address
        message = f"Wallet not found: {wallet_address}"
        super().__init__(message, {'wallet_address': wallet_address})


class MarketNotFoundError(DatabaseError):
    """Requested market not found in database."""

    def __init__(self, market_id: str):
        self.market_id = market_id
        message = f"Market not found: {market_id}"
        super().__init__(message, {'market_id': market_id})


# =============================================================================
# Detection Related Errors
# =============================================================================

class DetectionError(CrystalBallError):
    """Base class for detection-related errors."""
    pass


class SignalProcessingError(DetectionError):
    """Error processing detection signal."""

    def __init__(self, signal_name: str, error_message: str,
                 wallet_address: Optional[str] = None,
                 market_id: Optional[str] = None):
        self.signal_name = signal_name
        self.wallet_address = wallet_address
        self.market_id = market_id

        details = {'signal_name': signal_name}
        if wallet_address:
            details['wallet_address'] = wallet_address
        if market_id:
            details['market_id'] = market_id

        message = f"Signal '{signal_name}' processing failed: {error_message}"
        super().__init__(message, details)


class InsufficientDataError(DetectionError):
    """Not enough data to perform detection."""

    def __init__(self, data_type: str, required_amount: Optional[str] = None,
                 available_amount: Optional[str] = None):
        self.data_type = data_type
        self.required_amount = required_amount
        self.available_amount = available_amount

        details = {'data_type': data_type}
        if required_amount:
            details['required_amount'] = required_amount
        if available_amount:
            details['available_amount'] = available_amount

        message = f"Insufficient {data_type} for detection"
        super().__init__(message, details)


class ScoringError(DetectionError):
    """Error calculating suspicion score."""

    def __init__(self, message: str, wallet_address: Optional[str] = None,
                 signal_scores: Optional[Dict[str, int]] = None):
        self.wallet_address = wallet_address
        self.signal_scores = signal_scores

        details = {}
        if wallet_address:
            details['wallet_address'] = wallet_address
        if signal_scores:
            details['signal_scores'] = signal_scores

        super().__init__(message, details)


# =============================================================================
# Telegram Related Errors
# =============================================================================

class TelegramError(CrystalBallError):
    """Base class for Telegram-related errors."""
    pass


class TelegramAuthError(TelegramError):
    """Telegram bot authentication failed."""

    def __init__(self, bot_token: Optional[str] = None):
        self.bot_token = bot_token[:10] + "..." if bot_token else None
        message = "Telegram bot authentication failed"
        details = {'bot_token_prefix': self.bot_token} if self.bot_token else {}
        super().__init__(message, details)


class TelegramSendError(TelegramError):
    """Failed to send Telegram message."""

    def __init__(self, message: str, chat_id: Optional[str] = None,
                 error_code: Optional[int] = None):
        self.chat_id = chat_id
        self.error_code = error_code

        details = {}
        if chat_id:
            details['chat_id'] = chat_id
        if error_code:
            details['error_code'] = error_code

        super().__init__(message, details)


class TelegramRateLimitError(TelegramError):
    """Telegram rate limit exceeded."""

    def __init__(self, retry_after: Optional[int] = None):
        self.retry_after = retry_after
        message = f"Telegram rate limit exceeded"
        if retry_after:
            message += f", retry after {retry_after} seconds"

        details = {'retry_after': retry_after} if retry_after else {}
        super().__init__(message, details)


# =============================================================================
# Configuration Related Errors
# =============================================================================

class ConfigurationError(CrystalBallError):
    """Base class for configuration-related errors."""
    pass


class MissingConfigError(ConfigurationError):
    """Required configuration missing."""

    def __init__(self, config_key: str, config_section: Optional[str] = None):
        self.config_key = config_key
        self.config_section = config_section

        message = f"Missing required configuration: {config_key}"
        if config_section:
            message = f"Missing required configuration: {config_section}.{config_key}"

        details = {'config_key': config_key}
        if config_section:
            details['config_section'] = config_section

        super().__init__(message, details)


class InvalidConfigError(ConfigurationError):
    """Configuration value is invalid."""

    def __init__(self, config_key: str, config_value: Any,
                 expected_format: Optional[str] = None):
        self.config_key = config_key
        self.config_value = config_value
        self.expected_format = expected_format

        message = f"Invalid configuration value for '{config_key}': {config_value}"
        if expected_format:
            message += f" (expected format: {expected_format})"

        details = {
            'config_key': config_key,
            'config_value': config_value
        }
        if expected_format:
            details['expected_format'] = expected_format

        super().__init__(message, details)


# =============================================================================
# Validation Related Errors
# =============================================================================

class ValidationError(CrystalBallError):
    """Input validation failed."""

    def __init__(self, field_name: str, field_value: Any, reason: str):
        self.field_name = field_name
        self.field_value = field_value
        self.reason = reason

        message = f"Validation failed for '{field_name}': {reason}"
        details = {
            'field_name': field_name,
            'field_value': field_value,
            'reason': reason
        }

        super().__init__(message, details)


class WalletAddressValidationError(ValidationError):
    """Wallet address validation failed."""

    def __init__(self, address: str, reason: str = "Invalid format"):
        super().__init__('wallet_address', address, reason)


class MarketIdValidationError(ValidationError):
    """Market ID validation failed."""

    def __init__(self, market_id: str, reason: str = "Invalid format"):
        super().__init__('market_id', market_id, reason)


# =============================================================================
# Circuit Breaker Related Errors
# =============================================================================

class CircuitBreakerError(CrystalBallError):
    """Circuit breaker related errors."""
    pass


class CircuitBreakerOpenError(CircuitBreakerError):
    """Circuit breaker is open, blocking requests."""

    def __init__(self, service_name: str, failure_count: int,
                 reset_time: Optional[float] = None):
        self.service_name = service_name
        self.failure_count = failure_count
        self.reset_time = reset_time

        message = f"Circuit breaker OPEN for {service_name} " \
                  f"(failures: {failure_count})"

        details = {
            'service_name': service_name,
            'failure_count': failure_count
        }
        if reset_time:
            details['reset_time'] = reset_time

        super().__init__(message, details)


class CircuitBreakerHalfOpenError(CircuitBreakerError):
    """Circuit breaker is half-open, testing requests."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        message = f"Circuit breaker HALF-OPEN for {service_name}, testing recovery"
        super().__init__(message, {'service_name': service_name})