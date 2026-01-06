"""
API security layer for protecting against abuse and attacks.

Provides input rate limiting, request validation, and abuse protection
for any API endpoints or user-facing interfaces in the application.
"""

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Callable
from functools import wraps
from ipaddress import AddressValueError, IPv4Address, IPv6Address
import hashlib
import structlog

from .rate_limiter import RateLimitConfig, TokenBucketRateLimiter
from .exceptions import APIClientError, APIRateLimitError, ValidationError
from .validation import validate_wallet_address, validate_market_id
from .secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


@dataclass
class SecurityConfig:
    """Configuration for API security features."""

    # Rate limiting
    requests_per_minute: int = 60          # Global rate limit per IP
    burst_requests: int = 10               # Burst allowance
    rate_limit_window_minutes: int = 5     # Rolling window size

    # Request size limits
    max_request_size_bytes: int = 1024 * 1024  # 1MB max request
    max_query_params: int = 20             # Max query parameters
    max_header_size: int = 8192            # Max header size

    # Abuse detection
    max_consecutive_errors: int = 5        # Errors before temp ban
    temp_ban_duration_minutes: int = 15    # Temporary ban duration
    suspicious_patterns_threshold: int = 3  # Patterns to trigger alert

    # Input validation
    max_wallet_address_requests: int = 10   # Max addresses per request
    max_market_id_requests: int = 20       # Max market IDs per request
    allowed_user_agents: Optional[Set[str]] = None  # Allowed user agents (None = all)

    # Security headers enforcement
    require_security_headers: bool = True   # Require security headers
    allowed_origins: Set[str] = field(default_factory=lambda: {"*"})  # CORS origins


class IPRateLimiter:
    """IP-based rate limiting with abuse detection."""

    def __init__(self, config: SecurityConfig):
        self.config = config
        self.ip_counters: Dict[str, deque] = defaultdict(deque)  # IP -> request timestamps
        self.ip_errors: Dict[str, int] = defaultdict(int)        # IP -> error count
        self.banned_ips: Dict[str, float] = {}                  # IP -> ban expiry time
        self.suspicious_ips: Set[str] = set()                   # IPs flagged as suspicious
        self._lock = asyncio.Lock()

    async def is_allowed(self, ip_address: str) -> tuple[bool, Optional[str]]:
        """
        Check if IP address is allowed to make requests.

        Args:
            ip_address: IP address to check

        Returns:
            Tuple of (is_allowed, reason_if_denied)
        """
        async with self._lock:
            current_time = time.time()

            # Check if IP is banned
            if ip_address in self.banned_ips:
                ban_expiry = self.banned_ips[ip_address]
                if current_time < ban_expiry:
                    remaining = int(ban_expiry - current_time)
                    return False, f"IP temporarily banned, {remaining} seconds remaining"
                else:
                    # Ban expired, remove from banned list
                    del self.banned_ips[ip_address]

            # Clean old requests outside window
            window_start = current_time - (self.config.rate_limit_window_minutes * 60)
            ip_requests = self.ip_counters[ip_address]

            while ip_requests and ip_requests[0] < window_start:
                ip_requests.popleft()

            # Check rate limit
            if len(ip_requests) >= self.config.requests_per_minute:
                # Check if this triggers suspicious activity
                if ip_address not in self.suspicious_ips:
                    self.suspicious_ips.add(ip_address)
                    logger.warning("suspicious_ip_detected",
                                 ip_address=ip_address,
                                 requests_in_window=len(ip_requests),
                                 reason="rate_limit_exceeded")

                return False, f"Rate limit exceeded: {len(ip_requests)} requests in {self.config.rate_limit_window_minutes} minutes"

            # Add current request
            ip_requests.append(current_time)

            return True, None

    async def record_error(self, ip_address: str, error_type: str):
        """Record an error for abuse detection."""
        async with self._lock:
            self.ip_errors[ip_address] += 1

            if self.ip_errors[ip_address] >= self.config.max_consecutive_errors:
                # Temporary ban
                ban_duration = self.config.temp_ban_duration_minutes * 60
                self.banned_ips[ip_address] = time.time() + ban_duration

                logger.warning("ip_temporarily_banned",
                             ip_address=ip_address,
                             error_count=self.ip_errors[ip_address],
                             ban_duration_minutes=self.config.temp_ban_duration_minutes,
                             error_type=error_type)

                # Reset error count
                self.ip_errors[ip_address] = 0

    async def record_success(self, ip_address: str):
        """Record a successful request (reduces error count)."""
        async with self._lock:
            if self.ip_errors[ip_address] > 0:
                self.ip_errors[ip_address] = max(0, self.ip_errors[ip_address] - 1)

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        current_time = time.time()

        return {
            "active_ips": len(self.ip_counters),
            "banned_ips": len(self.banned_ips),
            "suspicious_ips": len(self.suspicious_ips),
            "total_errors": sum(self.ip_errors.values()),
            "banned_ips_list": [
                {
                    "ip": ip,
                    "expires_in": max(0, int(expiry - current_time))
                }
                for ip, expiry in self.banned_ips.items()
                if expiry > current_time
            ]
        }


class RequestValidator:
    """Validates and sanitizes API requests."""

    def __init__(self, config: SecurityConfig):
        self.config = config

    async def validate_request_size(self, content_length: int, headers: Dict[str, str]) -> None:
        """Validate request size limits."""
        if content_length > self.config.max_request_size_bytes:
            raise APIClientError(
                f"Request too large: {content_length} bytes (max: {self.config.max_request_size_bytes})",
                status_code=413
            )

        # Check header size
        total_header_size = sum(len(k) + len(v) for k, v in headers.items())
        if total_header_size > self.config.max_header_size:
            raise APIClientError(
                f"Headers too large: {total_header_size} bytes (max: {self.config.max_header_size})",
                status_code=431
            )

    async def validate_user_agent(self, user_agent: Optional[str]) -> None:
        """Validate user agent if restrictions are configured."""
        if self.config.allowed_user_agents is not None:
            if not user_agent or user_agent not in self.config.allowed_user_agents:
                raise APIClientError(
                    "Invalid or missing User-Agent header",
                    status_code=400
                )

    async def validate_wallet_addresses(self, addresses: List[str]) -> List[str]:
        """
        Validate a list of wallet addresses.

        Args:
            addresses: List of wallet addresses to validate

        Returns:
            List of validated addresses

        Raises:
            ValidationError: If any address is invalid
        """
        if len(addresses) > self.config.max_wallet_address_requests:
            raise ValidationError(
                "wallet_addresses",
                addresses,
                f"Too many addresses: {len(addresses)} (max: {self.config.max_wallet_address_requests})"
            )

        validated = []
        for i, address in enumerate(addresses):
            try:
                validated_address = validate_wallet_address(address)
                validated.append(validated_address)
            except Exception as e:
                raise ValidationError(
                    f"wallet_address[{i}]",
                    address,
                    f"Invalid wallet address: {e}"
                )

        return validated

    async def validate_market_ids(self, market_ids: List[str]) -> List[str]:
        """
        Validate a list of market IDs.

        Args:
            market_ids: List of market IDs to validate

        Returns:
            List of validated market IDs

        Raises:
            ValidationError: If any market ID is invalid
        """
        if len(market_ids) > self.config.max_market_id_requests:
            raise ValidationError(
                "market_ids",
                market_ids,
                f"Too many market IDs: {len(market_ids)} (max: {self.config.max_market_id_requests})"
            )

        validated = []
        for i, market_id in enumerate(market_ids):
            try:
                validated_id = validate_market_id(market_id)
                validated.append(validated_id)
            except Exception as e:
                raise ValidationError(
                    f"market_id[{i}]",
                    market_id,
                    f"Invalid market ID: {e}"
                )

        return validated

    async def validate_query_params(self, params: Dict[str, Any]) -> None:
        """Validate query parameters."""
        if len(params) > self.config.max_query_params:
            raise APIClientError(
                f"Too many query parameters: {len(params)} (max: {self.config.max_query_params})",
                status_code=400
            )

        # Check for common injection patterns
        dangerous_patterns = [
            '<script', 'javascript:', 'data:text/html',
            'SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ',
            'UNION ', 'DROP ', 'CREATE ', 'ALTER '
        ]

        for key, value in params.items():
            str_value = str(value).lower()
            for pattern in dangerous_patterns:
                if pattern.lower() in str_value:
                    logger.warning("suspicious_query_param_detected",
                                 key=key,
                                 pattern=pattern)
                    raise APIClientError(
                        f"Suspicious query parameter: {key}",
                        status_code=400
                    )


class APISecurityMiddleware:
    """
    Comprehensive API security middleware.

    Combines rate limiting, request validation, and abuse protection
    into a single middleware that can be applied to any API endpoint.
    """

    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.ip_limiter = IPRateLimiter(self.config)
        self.validator = RequestValidator(self.config)

        # Track request patterns for anomaly detection
        self.request_patterns: Dict[str, List[float]] = defaultdict(list)

        logger.info("api_security_middleware_initialized",
                   requests_per_minute=self.config.requests_per_minute,
                   max_request_size=self.config.max_request_size_bytes)

    def get_client_ip(self, headers: Dict[str, str], remote_addr: str = "127.0.0.1") -> str:
        """Extract client IP from headers with proxy support."""
        # Check common proxy headers
        ip_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Client-IP',
            'CF-Connecting-IP'
        ]

        for header in ip_headers:
            ip_value = headers.get(header)
            if ip_value:
                # Take first IP if comma-separated
                ip = ip_value.split(',')[0].strip()
                try:
                    # Validate IP format
                    IPv4Address(ip)
                    return ip
                except AddressValueError:
                    try:
                        IPv6Address(ip)
                        return ip
                    except AddressValueError:
                        continue

        return remote_addr

    async def process_request(self,
                            method: str,
                            path: str,
                            headers: Dict[str, str],
                            query_params: Dict[str, Any],
                            content_length: int = 0,
                            remote_addr: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Process incoming request through security checks.

        Args:
            method: HTTP method
            path: Request path
            headers: Request headers
            query_params: Query parameters
            content_length: Request body size
            remote_addr: Remote address

        Returns:
            Request metadata for logging

        Raises:
            APIClientError: If request violates security policies
            APIRateLimitError: If rate limit exceeded
        """
        start_time = time.time()
        client_ip = self.get_client_ip(headers, remote_addr)

        try:
            # Rate limiting check
            allowed, deny_reason = await self.ip_limiter.is_allowed(client_ip)
            if not allowed:
                await self.ip_limiter.record_error(client_ip, "rate_limit")
                raise APIRateLimitError(deny_reason, endpoint=path)

            # Request size validation
            await self.validator.validate_request_size(content_length, headers)

            # User agent validation
            await self.validator.validate_user_agent(headers.get('User-Agent'))

            # Query parameter validation
            await self.validator.validate_query_params(query_params)

            # Security header checks
            if self.config.require_security_headers:
                await self._validate_security_headers(headers)

            # Record successful validation
            await self.ip_limiter.record_success(client_ip)

            # Track request patterns
            await self._track_request_pattern(client_ip, method, path)

            processing_time = (time.time() - start_time) * 1000

            logger.info("api_request_processed",
                       client_ip=client_ip[:10] + "***",  # Partially redact IP
                       method=method,
                       path=path,
                       processing_time_ms=processing_time)

            return {
                "client_ip": client_ip,
                "processing_time_ms": processing_time,
                "validated": True
            }

        except Exception as e:
            # Record error for abuse detection
            error_type = type(e).__name__
            await self.ip_limiter.record_error(client_ip, error_type)

            processing_time = (time.time() - start_time) * 1000

            logger.warning("api_request_rejected",
                          client_ip=client_ip[:10] + "***",
                          method=method,
                          path=path,
                          error=str(e),
                          error_type=error_type,
                          processing_time_ms=processing_time)

            raise

    async def _validate_security_headers(self, headers: Dict[str, str]) -> None:
        """Validate security-related headers."""
        # This is a placeholder for security header validation
        # In a real implementation, you might check for:
        # - CSRF tokens
        # - API keys
        # - Authorization headers
        pass

    async def _track_request_pattern(self, ip: str, method: str, path: str) -> None:
        """Track request patterns for anomaly detection."""
        current_time = time.time()
        pattern_key = f"{ip}:{method}:{path}"

        # Keep only last 100 requests per pattern
        self.request_patterns[pattern_key].append(current_time)
        if len(self.request_patterns[pattern_key]) > 100:
            self.request_patterns[pattern_key] = self.request_patterns[pattern_key][-100:]

        # Simple anomaly detection: check for rapid repeated requests
        recent_requests = [
            t for t in self.request_patterns[pattern_key]
            if current_time - t < 60  # Last minute
        ]

        if len(recent_requests) >= self.config.suspicious_patterns_threshold:
            intervals = [
                recent_requests[i] - recent_requests[i-1]
                for i in range(1, len(recent_requests))
            ]
            avg_interval = sum(intervals) / len(intervals) if intervals else 0

            if avg_interval < 1.0:  # Less than 1 second between requests
                logger.warning("suspicious_request_pattern",
                             client_ip=ip[:10] + "***",
                             method=method,
                             path=path,
                             requests_per_minute=len(recent_requests),
                             avg_interval=avg_interval)

    def get_security_stats(self) -> Dict[str, Any]:
        """Get security middleware statistics."""
        return {
            "ip_limiter": self.ip_limiter.get_stats(),
            "tracked_patterns": len(self.request_patterns),
            "config": {
                "requests_per_minute": self.config.requests_per_minute,
                "max_request_size": self.config.max_request_size_bytes,
                "security_headers_required": self.config.require_security_headers
            }
        }


def api_security_required(config: Optional[SecurityConfig] = None):
    """
    Decorator for applying API security to functions.

    Usage:
        @api_security_required()
        async def my_api_endpoint(request_data):
            # Your API logic here
            pass
    """
    middleware = APISecurityMiddleware(config)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request information from arguments
            # This is a simplified implementation - real implementation
            # would depend on the web framework being used

            request_info = {
                "method": "GET",
                "path": "/api/endpoint",
                "headers": {},
                "query_params": {},
                "content_length": 0,
                "remote_addr": "127.0.0.1"
            }

            # Process through security middleware
            await middleware.process_request(**request_info)

            # Execute original function
            return await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)

        return wrapper
    return decorator


# Global middleware instance
_global_middleware: Optional[APISecurityMiddleware] = None


def get_api_security_middleware() -> APISecurityMiddleware:
    """Get or create global API security middleware."""
    global _global_middleware
    if _global_middleware is None:
        _global_middleware = APISecurityMiddleware()
    return _global_middleware


def test_api_security():
    """Test API security functionality."""
    print("🔒 Testing API Security")
    print("=" * 30)

    async def run_tests():
        middleware = APISecurityMiddleware()

        # Test normal request
        try:
            result = await middleware.process_request(
                method="GET",
                path="/api/wallets",
                headers={"User-Agent": "test-client"},
                query_params={"limit": "10"},
                content_length=100
            )
            print(f"✅ Normal request: {result['validated']}")
        except Exception as e:
            print(f"❌ Normal request failed: {e}")

        # Test rate limiting
        print("\nTesting rate limiting...")
        ip_limiter = IPRateLimiter(SecurityConfig(requests_per_minute=2))

        for i in range(5):
            allowed, reason = await ip_limiter.is_allowed("192.168.1.1")
            print(f"  Request {i+1}: {'✅' if allowed else '❌'} {reason or 'OK'}")

        # Test validation
        print("\nTesting validation...")
        validator = RequestValidator(SecurityConfig())

        try:
            addresses = await validator.validate_wallet_addresses([
                "0x742dE5a9b5fc17a187B86EC36B7b49B1B9F90a4f",
                "0x123456789012345678901234567890123456789a"
            ])
            print(f"✅ Address validation: {len(addresses)} valid addresses")
        except Exception as e:
            print(f"❌ Address validation failed: {e}")

        print("\n✅ API security test completed")

    asyncio.run(run_tests())


if __name__ == "__main__":
    test_api_security()