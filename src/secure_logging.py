"""
Secure logging configuration for Witcher's Crystal Ball.

Ensures that sensitive data (private keys, bot tokens, etc.) is never
logged, even accidentally. Provides sanitized logging utilities and
structured log processors that filter sensitive content.
"""

import re
import json
from typing import Any, Dict, Set, Union, Optional
from structlog.types import EventDict, WrappedLogger
import structlog


# Sensitive data patterns to redact from logs
SENSITIVE_PATTERNS = {
    # Private keys (Ethereum format)
    'private_key': re.compile(r'0x[a-fA-F0-9]{64}'),

    # Telegram bot tokens
    'bot_token': re.compile(r'\d+:[A-Za-z0-9_-]{35}'),

    # API keys (various formats)
    'api_key': re.compile(r'[A-Za-z0-9]{32,}'),

    # Credit card numbers
    'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),

    # Email addresses (partial redaction)
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),

    # URLs with auth tokens
    'auth_url': re.compile(r'https?://[^/]*:[^@]*@[^\s]+'),

    # JWT tokens
    'jwt': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
}

# Field names that commonly contain sensitive data
SENSITIVE_FIELD_NAMES = {
    'password', 'passwd', 'secret', 'token', 'key', 'auth', 'credential',
    'private_key', 'api_key', 'bot_token', 'telegram_bot_token',
    'polymarket_private_key', 'auth_header', 'authorization',
    'x-api-key', 'bearer', 'session_id', 'session_key'
}

# Field names for partial redaction (show first/last few characters)
PARTIALLY_REDACTED_FIELDS = {
    'wallet_address', 'address', 'market_id', 'token_id', 'chat_id'
}


def sanitize_string(text: str) -> str:
    """
    Sanitize a string by redacting sensitive patterns.

    Args:
        text: Input string to sanitize

    Returns:
        Sanitized string with sensitive data redacted
    """
    if not isinstance(text, str):
        return text

    sanitized = text

    # Apply all sensitive patterns
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        sanitized = pattern.sub(f'[REDACTED_{pattern_name.upper()}]', sanitized)

    return sanitized


def partially_redact(value: str, show_chars: int = 4) -> str:
    """
    Partially redact a string, showing only first and last few characters.

    Args:
        value: String to partially redact
        show_chars: Number of characters to show at start and end

    Returns:
        Partially redacted string
    """
    if not isinstance(value, str) or len(value) <= show_chars * 2:
        return value

    if len(value) <= 10:
        # For short strings, just show first few chars
        return f"{value[:3]}***"

    return f"{value[:show_chars]}***{value[-show_chars:]}"


def sanitize_dict(data: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
    """
    Recursively sanitize a dictionary.

    Args:
        data: Dictionary to sanitize
        depth: Current recursion depth (prevents infinite loops)

    Returns:
        Sanitized dictionary
    """
    if depth > 10:  # Prevent deep recursion
        return {"[DEEP_RECURSION]": "..."}

    if not isinstance(data, dict):
        return data

    sanitized = {}

    for key, value in data.items():
        key_lower = key.lower()

        # Check if field name indicates sensitive data
        if any(sensitive in key_lower for sensitive in SENSITIVE_FIELD_NAMES):
            sanitized[key] = '[REDACTED_SENSITIVE_FIELD]'

        # Check if field should be partially redacted
        elif any(partial in key_lower for partial in PARTIALLY_REDACTED_FIELDS):
            if isinstance(value, str):
                sanitized[key] = partially_redact(value)
            else:
                sanitized[key] = value

        # Recursively sanitize nested structures
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict(value, depth + 1)

        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_dict(item, depth + 1) if isinstance(item, dict)
                else sanitize_string(str(item)) if isinstance(item, str)
                else item
                for item in value
            ]

        # Sanitize string values
        elif isinstance(value, str):
            sanitized[key] = sanitize_string(value)

        else:
            sanitized[key] = value

    return sanitized


def secure_log_processor(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """
    Structlog processor that sanitizes log events.

    This processor ensures that sensitive data is never written to logs,
    even if it's accidentally included in log events.
    """
    # Sanitize the main event message
    if 'event' in event_dict:
        event_dict['event'] = sanitize_string(str(event_dict['event']))

    # Sanitize all other fields
    sanitized_event = {}
    for key, value in event_dict.items():
        if key == 'event':
            sanitized_event[key] = value  # Already sanitized above
        elif isinstance(value, str):
            sanitized_event[key] = sanitize_string(value)
        elif isinstance(value, dict):
            sanitized_event[key] = sanitize_dict(value)
        elif isinstance(value, list):
            sanitized_event[key] = [
                sanitize_dict(item) if isinstance(item, dict)
                else sanitize_string(str(item)) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            sanitized_event[key] = value

    return sanitized_event


def add_security_context(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """
    Add security-relevant context to log events.
    """
    # Add security markers for sensitive operations
    event = event_dict.get('event', '')

    if any(word in event.lower() for word in ['auth', 'login', 'token', 'key', 'secret']):
        event_dict['security_sensitive'] = True

    if any(word in event.lower() for word in ['fail', 'error', 'denied', 'unauthorized']):
        event_dict['security_event'] = True

    # Add component context
    if 'logger' in event_dict:
        logger_name = str(event_dict['logger'])
        if 'polymarket' in logger_name:
            event_dict['component'] = 'api_client'
        elif 'telegram' in logger_name:
            event_dict['component'] = 'notifications'
        elif 'database' in logger_name:
            event_dict['component'] = 'storage'
        elif 'detection' in logger_name:
            event_dict['component'] = 'analysis'

    return event_dict


def configure_secure_logging(log_level: str = "INFO", json_format: bool = False) -> None:
    """
    Configure secure logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        json_format: Whether to use JSON format for logs
    """
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        add_security_context,           # Add security context first
        secure_log_processor,           # Sanitize sensitive data
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


class SecureLogger:
    """
    Wrapper around structlog that provides additional security features.
    """

    def __init__(self, name: str):
        self.logger = structlog.get_logger(name)
        self.name = name

    def debug(self, event: str, **kwargs):
        """Log debug message with sanitization."""
        self.logger.debug(event, **self._sanitize_kwargs(kwargs))

    def info(self, event: str, **kwargs):
        """Log info message with sanitization."""
        self.logger.info(event, **self._sanitize_kwargs(kwargs))

    def warning(self, event: str, **kwargs):
        """Log warning message with sanitization."""
        self.logger.warning(event, **self._sanitize_kwargs(kwargs))

    def error(self, event: str, **kwargs):
        """Log error message with sanitization."""
        self.logger.error(event, **self._sanitize_kwargs(kwargs))

    def critical(self, event: str, **kwargs):
        """Log critical message with sanitization."""
        self.logger.critical(event, **self._sanitize_kwargs(kwargs))

    def _sanitize_kwargs(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize keyword arguments."""
        return sanitize_dict(kwargs)

    def audit_log(self, action: str, user: Optional[str] = None,
                  resource: Optional[str] = None, outcome: str = "success", **kwargs):
        """
        Log security audit events.

        Args:
            action: Action being performed
            user: User/component performing action
            resource: Resource being accessed
            outcome: success/failure/error
        """
        audit_data = {
            'audit_action': action,
            'audit_user': user or 'system',
            'audit_resource': resource,
            'audit_outcome': outcome,
            'component': self.name,
            **self._sanitize_kwargs(kwargs)
        }

        self.logger.info(f"AUDIT: {action}", **audit_data)


def get_secure_logger(name: str) -> SecureLogger:
    """Get a secure logger instance."""
    return SecureLogger(name)


def log_sensitive_operation(operation: str, component: str, success: bool = True,
                          details: Optional[Dict[str, Any]] = None):
    """
    Log a sensitive operation for security monitoring.

    Args:
        operation: Description of the operation
        component: Component performing the operation
        success: Whether operation was successful
        details: Additional details (will be sanitized)
    """
    logger = get_secure_logger("security")

    outcome = "success" if success else "failure"
    sanitized_details = sanitize_dict(details or {})

    logger.audit_log(
        action=operation,
        user=component,
        outcome=outcome,
        **sanitized_details
    )


def test_logging_security():
    """Test that sensitive data is properly redacted."""
    logger = get_secure_logger("test")

    # Test sensitive patterns
    test_cases = [
        {
            "private_key": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "bot_token": "123456789:ABCdefGHIjklMNOpqrsTUVwxyz-AbCdEfGhIjKlMnOpQrS",
            "wallet_address": "0x742dE5a9b5fc17a187B86EC36B7b49B1B9F90a4f",
            "market_id": "12345678901234567890",
            "normal_data": "This should not be redacted"
        }
    ]

    for case in test_cases:
        logger.info("Testing sensitive data logging", **case)

    # Test string sanitization
    sensitive_message = "Private key: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    logger.info(sensitive_message)

    print("✅ Logging security test completed. Check logs to verify redaction.")


if __name__ == "__main__":
    # Configure secure logging
    configure_secure_logging(json_format=False)

    # Run test
    test_logging_security()