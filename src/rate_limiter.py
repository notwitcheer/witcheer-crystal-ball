"""
Rate limiting implementation for API calls.

Provides token bucket and sliding window rate limiting algorithms
to prevent API abuse and ensure compliance with service limits.
"""

import time
import asyncio
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from collections import deque
from functools import wraps
import structlog

from .exceptions import APIRateLimitError

logger = structlog.get_logger(__name__)


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""

    requests_per_second: float = 2.0    # Default 2 requests per second
    burst_size: int = 5                 # Allow burst of 5 requests
    time_window_seconds: float = 60.0   # Sliding window of 60 seconds
    retry_after_seconds: float = 1.0    # Default retry delay

    # Adaptive rate limiting
    adaptive: bool = True               # Adjust limits based on response headers
    min_rate: float = 0.5              # Minimum rate when backing off
    max_rate: float = 10.0             # Maximum rate when speeding up
    backoff_factor: float = 0.5        # Multiply rate by this on 429
    speedup_factor: float = 1.1        # Multiply rate by this on success


class TokenBucketRateLimiter:
    """Token bucket rate limiter implementation."""

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.tokens = float(config.burst_size)  # Start with full bucket
        self.last_refill = time.time()
        self.current_rate = config.requests_per_second
        self._lock = asyncio.Lock()

        # Stats
        self.total_requests = 0
        self.rejected_requests = 0
        self.last_rate_adjustment = time.time()

        logger.info("rate_limiter_created",
                   requests_per_second=config.requests_per_second,
                   burst_size=config.burst_size,
                   adaptive=config.adaptive)

    async def _refill_tokens(self):
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill

        # Add tokens based on current rate
        tokens_to_add = elapsed * self.current_rate
        self.tokens = min(self.config.burst_size, self.tokens + tokens_to_add)
        self.last_refill = now

        logger.debug("tokens_refilled",
                    tokens=self.tokens,
                    elapsed=elapsed,
                    current_rate=self.current_rate)

    async def acquire(self, tokens: float = 1.0) -> bool:
        """
        Try to acquire tokens for rate limiting.

        Args:
            tokens: Number of tokens to acquire (default 1.0)

        Returns:
            True if tokens acquired, False if rate limited
        """
        async with self._lock:
            await self._refill_tokens()

            if self.tokens >= tokens:
                self.tokens -= tokens
                self.total_requests += 1
                logger.debug("rate_limit_acquired",
                           tokens_used=tokens,
                           tokens_remaining=self.tokens)
                return True
            else:
                self.rejected_requests += 1
                logger.warning("rate_limit_rejected",
                             tokens_requested=tokens,
                             tokens_available=self.tokens,
                             current_rate=self.current_rate)
                return False

    async def wait_for_token(self, tokens: float = 1.0) -> None:
        """
        Wait until tokens are available.

        Args:
            tokens: Number of tokens needed
        """
        while not await self.acquire(tokens):
            # Calculate wait time based on token deficit
            deficit = tokens - self.tokens
            wait_time = deficit / self.current_rate

            # Add small buffer to ensure tokens are available
            wait_time = max(wait_time + 0.1, self.config.retry_after_seconds)

            logger.info("rate_limit_waiting",
                       wait_time=wait_time,
                       tokens_needed=tokens,
                       current_rate=self.current_rate)

            await asyncio.sleep(wait_time)

    def adjust_rate(self, response_headers: Optional[Dict[str, str]] = None,
                   is_rate_limited: bool = False):
        """
        Adjust rate based on API response.

        Args:
            response_headers: HTTP response headers
            is_rate_limited: Whether request was rate limited
        """
        if not self.config.adaptive:
            return

        now = time.time()
        old_rate = self.current_rate

        if is_rate_limited:
            # Reduce rate on rate limiting
            self.current_rate = max(
                self.config.min_rate,
                self.current_rate * self.config.backoff_factor
            )
            logger.warning("rate_limit_reduced",
                          old_rate=old_rate,
                          new_rate=self.current_rate,
                          reason="rate_limited")

        # Check for rate limit headers
        elif response_headers:
            retry_after = response_headers.get('Retry-After')
            if retry_after:
                try:
                    delay = float(retry_after)
                    # Adjust rate based on retry-after
                    suggested_rate = 1.0 / delay if delay > 0 else self.config.min_rate
                    self.current_rate = max(self.config.min_rate, suggested_rate)
                    logger.info("rate_limit_adjusted_by_header",
                               old_rate=old_rate,
                               new_rate=self.current_rate,
                               retry_after=delay)
                except ValueError:
                    pass

            # Check X-RateLimit headers
            remaining = response_headers.get('X-RateLimit-Remaining')
            reset = response_headers.get('X-RateLimit-Reset')
            if remaining and reset:
                try:
                    remaining_requests = int(remaining)
                    reset_time = int(reset)
                    time_remaining = reset_time - now

                    if time_remaining > 0 and remaining_requests > 0:
                        suggested_rate = remaining_requests / time_remaining
                        suggested_rate = min(self.config.max_rate, suggested_rate * 0.9)  # 90% of limit

                        if suggested_rate != self.current_rate:
                            self.current_rate = max(self.config.min_rate, suggested_rate)
                            logger.info("rate_limit_adjusted_by_headers",
                                       old_rate=old_rate,
                                       new_rate=self.current_rate,
                                       remaining=remaining_requests,
                                       time_remaining=time_remaining)
                except ValueError:
                    pass

        else:
            # Gradually increase rate on successful requests
            time_since_last_adjustment = now - self.last_rate_adjustment
            if time_since_last_adjustment > 60.0:  # Adjust at most once per minute
                self.current_rate = min(
                    self.config.max_rate,
                    self.current_rate * self.config.speedup_factor
                )
                self.last_rate_adjustment = now

                if self.current_rate != old_rate:
                    logger.debug("rate_limit_increased",
                                old_rate=old_rate,
                                new_rate=self.current_rate,
                                reason="success_pattern")

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        return {
            'current_rate': self.current_rate,
            'configured_rate': self.config.requests_per_second,
            'tokens_available': self.tokens,
            'total_requests': self.total_requests,
            'rejected_requests': self.rejected_requests,
            'rejection_rate': self.rejected_requests / max(self.total_requests, 1),
            'adaptive_enabled': self.config.adaptive
        }


class SlidingWindowRateLimiter:
    """Sliding window rate limiter implementation."""

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.requests: deque = deque()  # (timestamp, weight) tuples
        self._lock = asyncio.Lock()

        # Stats
        self.total_requests = 0
        self.rejected_requests = 0

    async def _cleanup_old_requests(self):
        """Remove requests outside the time window."""
        now = time.time()
        window_start = now - self.config.time_window_seconds

        while self.requests and self.requests[0][0] < window_start:
            self.requests.popleft()

    async def acquire(self, weight: float = 1.0) -> bool:
        """
        Try to acquire capacity in the sliding window.

        Args:
            weight: Weight of this request (default 1.0)

        Returns:
            True if capacity acquired, False if rate limited
        """
        async with self._lock:
            await self._cleanup_old_requests()

            # Calculate current usage in window
            current_usage = sum(req[1] for req in self.requests)
            max_usage = self.config.requests_per_second * self.config.time_window_seconds

            if current_usage + weight <= max_usage:
                now = time.time()
                self.requests.append((now, weight))
                self.total_requests += 1
                logger.debug("sliding_window_acquired",
                           weight=weight,
                           current_usage=current_usage,
                           max_usage=max_usage)
                return True
            else:
                self.rejected_requests += 1
                logger.warning("sliding_window_rejected",
                             weight=weight,
                             current_usage=current_usage,
                             max_usage=max_usage)
                return False

    def get_stats(self) -> Dict[str, Any]:
        """Get sliding window statistics."""
        current_usage = sum(req[1] for req in self.requests)
        max_usage = self.config.requests_per_second * self.config.time_window_seconds

        return {
            'current_usage': current_usage,
            'max_usage': max_usage,
            'utilization': current_usage / max_usage,
            'window_size': len(self.requests),
            'total_requests': self.total_requests,
            'rejected_requests': self.rejected_requests,
            'rejection_rate': self.rejected_requests / max(self.total_requests, 1)
        }


class RateLimiterRegistry:
    """Registry for managing multiple rate limiters."""

    def __init__(self):
        self.limiters: Dict[str, TokenBucketRateLimiter] = {}

    def get_limiter(self, name: str, config: Optional[RateLimitConfig] = None) -> TokenBucketRateLimiter:
        """Get or create a rate limiter."""
        if name not in self.limiters:
            config = config or RateLimitConfig()
            self.limiters[name] = TokenBucketRateLimiter(config)

        return self.limiters[name]

    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all rate limiters."""
        return {name: limiter.get_stats() for name, limiter in self.limiters.items()}


# Global registry
_registry = RateLimiterRegistry()


def get_rate_limiter(name: str, config: Optional[RateLimitConfig] = None) -> TokenBucketRateLimiter:
    """Get a rate limiter from the global registry."""
    return _registry.get_limiter(name, config)


def rate_limited(limiter_name: str, config: Optional[RateLimitConfig] = None,
                wait: bool = True, tokens: float = 1.0):
    """
    Decorator for rate limiting function calls.

    Args:
        limiter_name: Name of rate limiter to use
        config: Rate limiter configuration
        wait: Whether to wait for tokens or raise exception
        tokens: Number of tokens to consume

    Usage:
        @rate_limited("api_calls", config=RateLimitConfig(requests_per_second=1.0))
        async def api_call():
            return await httpx.get("https://api.example.com")
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            limiter = get_rate_limiter(limiter_name, config)

            if wait:
                await limiter.wait_for_token(tokens)
            else:
                if not await limiter.acquire(tokens):
                    raise APIRateLimitError(
                        f"Rate limit exceeded for {limiter_name}",
                        endpoint=func.__name__
                    )

            # Execute function and handle response
            try:
                result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)

                # If result has response info, use it for rate adjustment
                if hasattr(result, 'headers'):
                    limiter.adjust_rate(dict(result.headers))
                elif isinstance(result, tuple) and len(result) == 2:
                    # (data, response) tuple
                    data, response = result
                    if hasattr(response, 'headers'):
                        limiter.adjust_rate(dict(response.headers))

                return result

            except APIRateLimitError:
                # Adjust rate on rate limiting
                limiter.adjust_rate(is_rate_limited=True)
                raise

        return wrapper
    return decorator


# Pre-configured rate limiters for common services
def get_polymarket_rate_limiter() -> TokenBucketRateLimiter:
    """Get rate limiter configured for Polymarket API."""
    config = RateLimitConfig(
        requests_per_second=2.0,    # Conservative rate
        burst_size=3,               # Small burst allowance
        adaptive=True,              # Adapt to API responses
        min_rate=0.5,              # Don't go below 0.5 RPS
        max_rate=5.0               # Don't exceed 5 RPS
    )
    return get_rate_limiter("polymarket_api", config)


def get_telegram_rate_limiter() -> TokenBucketRateLimiter:
    """Get rate limiter configured for Telegram API."""
    config = RateLimitConfig(
        requests_per_second=1.0,    # Telegram allows 30 msgs/sec but we're conservative
        burst_size=5,               # Allow small burst for multiple alerts
        adaptive=False,             # Telegram limits are well documented
        min_rate=0.2,              # Very conservative minimum
        max_rate=3.0               # Conservative maximum
    )
    return get_rate_limiter("telegram_api", config)


def get_all_rate_limiter_stats() -> Dict[str, Dict[str, Any]]:
    """Get statistics for all rate limiters."""
    return _registry.get_all_stats()