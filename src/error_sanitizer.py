"""
Error message sanitization for user-facing outputs.

Ensures that error messages shown to users don't contain sensitive information
like private keys, internal paths, API tokens, or detailed system information
that could be useful to attackers.
"""

import re
import traceback
from typing import Any, Dict, Optional, Union
from pathlib import Path

from .secure_logging import SENSITIVE_PATTERNS, sanitize_string
from .exceptions import CrystalBallError


# Patterns for internal information to remove from user-facing errors
INTERNAL_PATTERNS = {
    # File paths
    'file_path': re.compile(r'/[a-zA-Z0-9_./\-]+'),

    # IP addresses
    'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),

    # Stack traces
    'stack_trace': re.compile(r'File "[^"]*", line \d+, in [^\n]*\n[^\n]*'),

    # Python module paths
    'module_path': re.compile(r'[a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+\.[a-zA-Z0-9_]+'),

    # Database connection strings
    'db_connection': re.compile(r'://[^/]+@[^/]+/'),

    # URLs with credentials
    'credential_url': re.compile(r'https?://[^:]+:[^@]+@[^\s]+'),

    # Internal class/function names
    'internal_class': re.compile(r'<[^>]*\.[^>]*>'),

    # Memory addresses
    'memory_address': re.compile(r'0x[0-9a-fA-F]+'),

    # Version numbers that might leak system info
    'version_info': re.compile(r'\bv?\d+\.\d+\.\d+[\w.-]*\b'),
}

# Generic error messages for different categories
GENERIC_MESSAGES = {
    'api_error': "Unable to connect to external service. Please try again later.",
    'auth_error': "Authentication failed. Please check your credentials.",
    'network_error': "Network connection error. Please check your internet connection.",
    'database_error': "Database operation failed. Please contact support if the issue persists.",
    'config_error': "Configuration error. Please check your settings.",
    'validation_error': "Invalid input provided.",
    'permission_error': "Insufficient permissions for this operation.",
    'not_found_error': "Requested resource not found.",
    'rate_limit_error': "Too many requests. Please wait before trying again.",
    'timeout_error': "Operation timed out. Please try again.",
    'unknown_error': "An unexpected error occurred. Please contact support."
}

# Mapping of exception types to generic message categories
EXCEPTION_MESSAGE_MAPPING = {
    # API related
    'PolymarketAPIError': 'api_error',
    'APIAuthenticationError': 'auth_error',
    'APIRateLimitError': 'rate_limit_error',
    'APITimeoutError': 'timeout_error',
    'APIConnectionError': 'network_error',
    'APIServerError': 'api_error',
    'APIClientError': 'api_error',

    # Database related
    'DatabaseError': 'database_error',
    'DatabaseConnectionError': 'database_error',
    'DatabaseMigrationError': 'database_error',
    'DatabaseIntegrityError': 'database_error',
    'WalletNotFoundError': 'not_found_error',
    'MarketNotFoundError': 'not_found_error',

    # Telegram related
    'TelegramError': 'api_error',
    'TelegramAuthError': 'auth_error',
    'TelegramSendError': 'api_error',
    'TelegramRateLimitError': 'rate_limit_error',

    # Configuration related
    'ConfigurationError': 'config_error',
    'MissingConfigError': 'config_error',
    'InvalidConfigError': 'config_error',

    # Validation related
    'ValidationError': 'validation_error',
    'WalletAddressValidationError': 'validation_error',
    'MarketIdValidationError': 'validation_error',

    # Circuit breaker
    'CircuitBreakerOpenError': 'api_error',
    'CircuitBreakerHalfOpenError': 'api_error',

    # Python built-ins
    'ConnectionError': 'network_error',
    'TimeoutError': 'timeout_error',
    'PermissionError': 'permission_error',
    'FileNotFoundError': 'not_found_error',
    'ValueError': 'validation_error',
    'KeyError': 'validation_error',
    'TypeError': 'validation_error',
}


def sanitize_error_message(error: Union[Exception, str],
                          include_error_id: bool = True) -> str:
    """
    Sanitize an error message for user consumption.

    Args:
        error: Exception or error message string
        include_error_id: Whether to include error ID for support

    Returns:
        Sanitized error message safe for user display
    """
    if isinstance(error, Exception):
        error_type = error.__class__.__name__
        error_message = str(error)
    else:
        error_type = 'Unknown'
        error_message = str(error)

    # Start with original message
    sanitized = error_message

    # Remove sensitive patterns
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        sanitized = pattern.sub(f'[REDACTED]', sanitized)

    # Remove internal information
    for pattern_name, pattern in INTERNAL_PATTERNS.items():
        sanitized = pattern.sub(f'[{pattern_name.upper()}]', sanitized)

    # Check if we should use a generic message instead
    if error_type in EXCEPTION_MESSAGE_MAPPING:
        generic_category = EXCEPTION_MESSAGE_MAPPING[error_type]
        generic_message = GENERIC_MESSAGES[generic_category]

        # Decide whether to use generic or sanitized specific message
        if _should_use_generic_message(sanitized, error_type):
            sanitized = generic_message
        else:
            # Use sanitized specific message but add context
            sanitized = f"{generic_message} (Details: {sanitized[:100]}...)"

    # Add error ID for support purposes
    if include_error_id and isinstance(error, Exception):
        error_id = _generate_error_id(error)
        sanitized += f" [Error ID: {error_id}]"

    return sanitized.strip()


def _should_use_generic_message(sanitized_message: str, error_type: str) -> bool:
    """
    Determine if we should use a generic message instead of the sanitized one.

    Args:
        sanitized_message: The sanitized error message
        error_type: Type of exception

    Returns:
        True if generic message should be used
    """
    # Use generic for highly technical errors
    technical_indicators = [
        '[FILE_PATH]', '[MODULE_PATH]', '[STACK_TRACE]', '[MEMORY_ADDRESS]',
        'Traceback', 'in <module>', '__', 'NoneType', 'object has no attribute'
    ]

    if any(indicator in sanitized_message for indicator in technical_indicators):
        return True

    # Use generic for certain error types
    always_generic_types = {
        'DatabaseIntegrityError', 'CircuitBreakerOpenError', 'InternalError'
    }

    if error_type in always_generic_types:
        return True

    # Use generic if message is mostly redacted
    redacted_ratio = sanitized_message.count('[REDACTED]') / max(len(sanitized_message.split()), 1)
    if redacted_ratio > 0.3:  # More than 30% redacted
        return True

    return False


def _generate_error_id(error: Exception) -> str:
    """Generate a unique error ID for support purposes."""
    import hashlib
    import time

    # Create hash from error details
    error_details = f"{error.__class__.__name__}:{str(error)}:{time.time()}"
    error_hash = hashlib.md5(error_details.encode()).hexdigest()[:8]

    return f"ERR-{error_hash.upper()}"


class SanitizedError(Exception):
    """
    Exception that always provides sanitized user-friendly messages.
    """

    def __init__(self, original_error: Exception, user_message: Optional[str] = None):
        self.original_error = original_error
        self.error_id = _generate_error_id(original_error)

        # Generate user-friendly message
        if user_message:
            self.user_message = user_message
        else:
            self.user_message = sanitize_error_message(original_error)

        super().__init__(self.user_message)

    def get_technical_details(self) -> Dict[str, Any]:
        """Get technical details for internal logging."""
        return {
            'error_id': self.error_id,
            'original_type': self.original_error.__class__.__name__,
            'original_message': str(self.original_error),
            'user_message': self.user_message,
            'traceback': traceback.format_exception(
                type(self.original_error),
                self.original_error,
                self.original_error.__traceback__
            ) if self.original_error.__traceback__ else None
        }


def safe_error_handler(func):
    """
    Decorator that converts exceptions to sanitized user-friendly errors.

    Usage:
        @safe_error_handler
        def user_facing_function():
            # This function might raise technical exceptions
            pass
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except CrystalBallError as e:
            # Our custom errors already have context
            raise SanitizedError(e)
        except Exception as e:
            # Convert any other exception to sanitized error
            raise SanitizedError(e)

    return wrapper


def create_user_error_response(error: Exception,
                             context: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a standardized error response for user interfaces.

    Args:
        error: The exception that occurred
        context: Additional context about where error occurred

    Returns:
        Dictionary with error information safe for user display
    """
    sanitized = SanitizedError(error)

    response = {
        'success': False,
        'error': {
            'message': sanitized.user_message,
            'error_id': sanitized.error_id,
            'type': 'error',
        }
    }

    if context:
        response['error']['context'] = context

    # Add retry information for certain errors
    if isinstance(error, (ConnectionError, TimeoutError)) or 'network' in str(error).lower():
        response['error']['retryable'] = True
        response['error']['retry_after'] = 30  # seconds

    return response


def log_sanitized_error(logger, error: Exception, context: Optional[str] = None):
    """
    Log an error with both sanitized user message and full technical details.

    Args:
        logger: Logger instance
        error: Exception to log
        context: Additional context
    """
    sanitized = SanitizedError(error)
    technical_details = sanitized.get_technical_details()

    # Log the sanitized version at INFO level (safe for user-visible logs)
    logger.info(
        "user_error_occurred",
        user_message=sanitized.user_message,
        error_id=sanitized.error_id,
        context=context or "unknown"
    )

    # Log technical details at DEBUG level (internal only)
    logger.debug(
        "technical_error_details",
        **technical_details,
        context=context or "unknown"
    )


def test_error_sanitization():
    """Test error message sanitization."""
    import traceback

    print("🔒 Testing Error Message Sanitization")
    print("=" * 50)

    # Test cases with sensitive information
    test_errors = [
        ValueError("Invalid private key: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
        ConnectionError("Failed to connect to https://user:pass@api.example.com/endpoint"),
        FileNotFoundError("/home/user/.secrets/private_key.txt not found"),
        Exception("Database error: connection string postgresql://user:password@localhost:5432/db failed"),
        RuntimeError("API token 123456789:ABCdefGHIjklMNOpqrsTUVwxyz-AbCdEfGhIjKlMnOpQrS is invalid"),
    ]

    for i, error in enumerate(test_errors, 1):
        print(f"\nTest {i}:")
        print(f"Original: {error}")
        sanitized = sanitize_error_message(error)
        print(f"Sanitized: {sanitized}")

    # Test with CrystalBallError
    try:
        from .exceptions import ValidationError
        validation_error = ValidationError("wallet_address", "0x1234...5678", "Invalid format")
        print(f"\nCustom Error Test:")
        print(f"Original: {validation_error}")
        print(f"Sanitized: {sanitize_error_message(validation_error)}")
    except ImportError:
        print("\nSkipping custom error test (import error)")

    print(f"\n✅ Error sanitization test completed!")


if __name__ == "__main__":
    test_error_sanitization()