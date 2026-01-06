# Security Implementation Guide

## Overview

This document outlines the comprehensive security measures implemented in Witcher's Crystal Ball to protect sensitive data and ensure secure operation.

## 🔒 Phase 1: Critical Security (Completed)

### Input Validation & Sanitization
- **File**: `src/validation.py`
- **Purpose**: Validates all external inputs before processing
- **Features**:
  - Ethereum wallet address validation (`0x[a-fA-F0-9]{40}`)
  - Market ID and token ID validation
  - Numeric data validation with Decimal precision
  - API response sanitization (XSS/injection protection)
  - Pydantic models for trade data validation

### Schema Validation
- **File**: `src/schemas.py`
- **Purpose**: Comprehensive Pydantic schemas for all external API data
- **Features**:
  - `PolymarketMarketSchema` for market data
  - `PolymarketEventSchema` for event data
  - `PolymarketTradeSchema` for trade data
  - `WalletAnalysisSchema` for internal wallet data
  - `SuspiciousActivitySchema` for alert data

### Enhanced Error Handling
- **File**: `src/exceptions.py`
- **Purpose**: Specific error types replacing generic exceptions
- **Features**:
  - API-specific errors: `PolymarketAPIError`, `APIAuthenticationError`
  - Database-specific errors: `DatabaseConnectionError`, `WalletNotFoundError`
  - Validation errors: `WalletAddressValidationError`, `MarketIdValidationError`
  - Circuit breaker errors: `CircuitBreakerOpenError`

### Circuit Breaker Pattern
- **File**: `src/circuit_breaker.py`
- **Purpose**: Prevents cascading failures from external API issues
- **Features**:
  - Three states: CLOSED, OPEN, HALF_OPEN
  - Configurable failure/success thresholds
  - Automatic rate adjustment based on API responses
  - Pre-configured breakers for Polymarket and Telegram APIs

### Graceful Degradation
- **File**: `src/graceful_degradation.py`
- **Purpose**: Maintains functionality when external services fail
- **Features**:
  - Cached data fallback with expiration
  - Degraded service modes: FULL → DEGRADED → MINIMAL → UNAVAILABLE
  - Retry logic with exponential backoff
  - Specialized degraded providers for market data and notifications

## 🟡 Phase 2: Immediate Security (Completed)

### Secrets Management
- **Files**: `src/secrets_manager.py`, `src/secure_config.py`
- **Purpose**: Secure storage and retrieval of sensitive data
- **Features**:
  - Encrypted file storage with password protection
  - Multiple backend support (encrypted file, environment fallback)
  - Automatic migration from `.env` files
  - Secure private key and token management
  - No plain text secrets in configuration files

### Rate Limiting
- **File**: `src/rate_limiter.py`
- **Purpose**: Prevent API abuse and ensure compliance with service limits
- **Features**:
  - Token bucket algorithm with burst support
  - Sliding window rate limiting
  - Adaptive rate adjustment based on API responses
  - Pre-configured limiters for different services
  - Comprehensive statistics and monitoring

### Secure Logging
- **File**: `src/secure_logging.py`
- **Purpose**: Ensure no sensitive data is written to logs
- **Features**:
  - Automatic redaction of sensitive patterns (private keys, tokens, etc.)
  - Partial redaction for identifiers (wallet addresses, market IDs)
  - Structured logging with security context
  - Audit logging for security-sensitive operations
  - Configurable log processors and formatters

### Error Message Sanitization
- **File**: `src/error_sanitizer.py`
- **Purpose**: Prevent sensitive data exposure in user-facing error messages
- **Features**:
  - Automatic removal of sensitive patterns from error messages
  - Generic error messages for technical errors
  - Error ID generation for support purposes
  - Sanitized error response creation
  - Separation of user-visible and internal technical details

## 🟠 Phase 3: Important Security (Completed)

### Database Security & Encryption
- **Files**: `src/database_encryption.py`, `src/storage/secure_database.py`
- **Purpose**: Encrypt sensitive data at rest in the database
- **Features**:
  - Transparent field-level encryption using Fernet (AES 128 CBC)
  - PBKDF2 key derivation from master password
  - Encrypted storage for wallet addresses, trade details, alert metadata
  - Partial encryption for searchable fields (wallet address prefixes)
  - Audit trail for all database operations
  - Automatic encryption/decryption during database operations
  - Migration tools for moving from unencrypted to encrypted storage

### API Input Security & Rate Limiting
- **File**: `src/api_security.py`
- **Purpose**: Protect against API abuse and malicious inputs
- **Features**:
  - IP-based rate limiting with abuse detection
  - Request size and header validation
  - Suspicious pattern detection in query parameters
  - Temporary IP banning for repeated violations
  - Input validation for wallet addresses and market IDs
  - Security header enforcement
  - Request pattern anomaly detection
  - Comprehensive security middleware for API endpoints

### Security Monitoring & Alerting
- **File**: `src/security_monitoring.py`
- **Purpose**: Monitor security events and send alerts for threats
- **Features**:
  - Real-time security event collection and analysis
  - Event aggregation to reduce alert noise
  - Multiple alert channels (Telegram, logs, custom handlers)
  - Severity-based alert prioritization (LOW/MEDIUM/HIGH/CRITICAL)
  - System health monitoring (circuit breakers, rate limiters)
  - Anomaly detection based on event patterns
  - Alert cooldowns to prevent spam
  - Comprehensive security metrics and reporting

### Configuration Validation
- **File**: `src/config_validator.py`
- **Purpose**: Validate all configuration at startup to prevent runtime errors
- **Features**:
  - Comprehensive validation of all settings and dependencies
  - Security configuration validation (encryption, secrets, permissions)
  - Database setup and connectivity validation
  - API configuration and credential validation
  - Telegram configuration validation
  - Detection algorithm parameter validation
  - File permissions and environment validation
  - Dependency availability checking
  - Detailed validation reports with suggestions for fixes

## 🔧 Security Configuration

### Setting up Encrypted Secrets Storage

1. **Generate a strong password** for secrets encryption:
   ```bash
   # Set environment variable
   export SECRETS_PASSWORD="your-strong-password-here"
   ```

2. **Migrate existing secrets** from `.env` to encrypted storage:
   ```bash
   python3 -m src.secure_config
   ```

3. **Remove sensitive data** from `.env` file and regenerate keys for maximum security.

### Configuring Rate Limiting

Rate limiting is automatically configured with conservative defaults:

- **Polymarket API**: 2 requests/second, adaptive adjustment
- **Telegram API**: 1 request/second, burst of 5 messages

Customize via `RateLimitConfig` in your application code.

### Enabling Secure Logging

Secure logging is enabled by default. To configure:

```python
from src.secure_logging import configure_secure_logging

# Configure with JSON format for production
configure_secure_logging(log_level="INFO", json_format=True)

# Use secure logger
from src.secure_logging import get_secure_logger
logger = get_secure_logger("my_component")

logger.info("Operation completed", user_data={"wallet": "0x123..."})
# Automatically sanitized: wallet becomes "0x12***678"
```

## 🚨 Security Best Practices

### For Developers

1. **Never log sensitive data** - Use `SecureLogger` instead of standard logging
2. **Validate all inputs** - Use validation functions from `src.validation`
3. **Handle errors properly** - Use specific exception types from `src.exceptions`
4. **Use rate limiting** - Apply `@rate_limited` decorator to API calls
5. **Check circuit breaker status** - Monitor service health via circuit breakers

### For Deployment

1. **Set strong secrets password** - Use at least 16 characters
2. **Remove `.env` secrets** - After migrating to encrypted storage
3. **Monitor logs** - Watch for security events and audit logs
4. **Regular backups** - Backup encrypted secrets file securely
5. **Update dependencies** - Keep all packages up to date

### For Operations

1. **Monitor circuit breakers** - Check API health regularly
2. **Review audit logs** - Check for unauthorized access attempts
3. **Rotate credentials** - Regularly update private keys and tokens
4. **Capacity planning** - Monitor rate limiting statistics
5. **Incident response** - Have procedures for security breaches

## 📊 Security Monitoring

### Key Metrics to Monitor

- **Circuit breaker states** - Open breakers indicate API issues
- **Rate limiting rejections** - High rejection rates indicate abuse or misconfiguration
- **Authentication failures** - Failed auth attempts may indicate attacks
- **Error rates by type** - Unusual error patterns may indicate issues
- **Audit log events** - Security-sensitive operations should be reviewed

### Log Analysis

Security-relevant logs are tagged with:
- `security_sensitive=true` - For sensitive operations
- `security_event=true` - For security failures/alerts
- `component=<name>` - For component identification
- `audit_*` fields - For audit trail events

## 🔄 Security Updates

This security implementation follows a layered defense approach:

1. **Input Layer** - Validation and sanitization of all external data
2. **Processing Layer** - Circuit breakers and graceful degradation
3. **Storage Layer** - Encrypted secrets and secure database operations
4. **Output Layer** - Sanitized error messages and secure logging
5. **Monitoring Layer** - Audit trails and security event detection

Regular security reviews should assess each layer for improvements and updates.

## 📞 Security Contact

For security-related issues or questions:
- Review this document and implementation
- Check logs for security events and audit trails
- Use error IDs for support when issues occur
- Follow secure development practices outlined above

---

**Note**: This security implementation is designed for research and educational purposes. Always follow additional security practices appropriate for your specific use case and environment.