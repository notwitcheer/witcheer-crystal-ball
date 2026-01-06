"""
Circuit breaker implementation for API failure protection.

Implements the Circuit Breaker pattern to prevent cascading failures
and provide graceful degradation when external APIs are unavailable.

Circuit Breaker States:
- CLOSED: Normal operation, requests pass through
- OPEN: Failures detected, requests fail immediately
- HALF_OPEN: Testing if service has recovered
"""

import time
import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional, Set
from functools import wraps
import structlog

from .exceptions import (
    CircuitBreakerOpenError,
    CircuitBreakerHalfOpenError,
    APIError,
    PolymarketAPIError,
    APITimeoutError,
    APIConnectionError,
    APIServerError
)

logger = structlog.get_logger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, blocking requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""

    failure_threshold: int = 5  # Failures before opening circuit
    success_threshold: int = 3  # Successes needed to close from half-open
    timeout: float = 60.0       # Seconds to wait before trying half-open
    reset_timeout: float = 300.0  # Seconds before resetting failure count

    # Which exceptions should be counted as failures
    failure_exceptions: Set[type] = field(default_factory=lambda: {
        APITimeoutError,
        APIConnectionError,
        APIServerError,
        PolymarketAPIError,
    })

    # Which exceptions should NOT count as failures (client errors, etc)
    success_exceptions: Set[type] = field(default_factory=lambda: {
        # Don't count validation errors or client errors as circuit failures
    })


class CircuitBreaker:
    """
    Circuit breaker for protecting against cascading failures.

    Usage:
        breaker = CircuitBreaker("polymarket_api", CircuitBreakerConfig())

        @breaker
        async def api_call():
            return await make_api_request()
    """

    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config

        # State tracking
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0.0
        self.last_success_time = 0.0

        # Async lock for thread safety
        self._lock = asyncio.Lock()

        # Metrics
        self.total_requests = 0
        self.total_failures = 0
        self.total_successes = 0

        logger.info("circuit_breaker_created",
                   name=name,
                   failure_threshold=config.failure_threshold,
                   timeout=config.timeout)

    async def __call__(self, func: Callable) -> Callable:
        """Decorator to wrap functions with circuit breaker."""

        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await self._execute(func, *args, **kwargs)

        return wrapper

    async def _execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        async with self._lock:
            await self._check_state()

        self.total_requests += 1

        try:
            # Execute the function
            result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)

            # Record success
            await self._on_success()
            return result

        except Exception as e:
            # Determine if this exception should trigger circuit failure
            await self._on_failure(e)
            raise

    async def _check_state(self):
        """Check and potentially update circuit state."""
        current_time = time.time()

        if self.state == CircuitState.OPEN:
            # Check if we should move to half-open
            if current_time - self.last_failure_time >= self.config.timeout:
                logger.info("circuit_breaker_half_open",
                           name=self.name,
                           failure_count=self.failure_count)
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0

        elif self.state == CircuitState.CLOSED:
            # Reset failure count after reset timeout
            if (self.failure_count > 0 and
                current_time - self.last_failure_time >= self.config.reset_timeout):
                logger.info("circuit_breaker_reset_failures",
                           name=self.name,
                           old_failure_count=self.failure_count)
                self.failure_count = 0

        # Block requests if circuit is open
        if self.state == CircuitState.OPEN:
            raise CircuitBreakerOpenError(
                self.name,
                self.failure_count,
                self.last_failure_time + self.config.timeout
            )

        # Limit requests if circuit is half-open
        elif self.state == CircuitState.HALF_OPEN:
            # Only allow one request at a time in half-open state
            # This is a simplified implementation
            pass

    async def _on_success(self):
        """Handle successful execution."""
        async with self._lock:
            self.total_successes += 1
            self.last_success_time = time.time()

            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1

                # If we have enough successes, close the circuit
                if self.success_count >= self.config.success_threshold:
                    logger.info("circuit_breaker_closed",
                               name=self.name,
                               success_count=self.success_count)
                    self.state = CircuitState.CLOSED
                    self.failure_count = 0
                    self.success_count = 0

    async def _on_failure(self, exception: Exception):
        """Handle failed execution."""
        # Check if this exception should count as a circuit failure
        if not self._should_record_failure(exception):
            return

        async with self._lock:
            self.total_failures += 1
            self.failure_count += 1
            self.last_failure_time = time.time()

            logger.warning("circuit_breaker_failure",
                          name=self.name,
                          failure_count=self.failure_count,
                          exception_type=type(exception).__name__,
                          exception_message=str(exception))

            # Open circuit if failure threshold reached
            if (self.state == CircuitState.CLOSED and
                self.failure_count >= self.config.failure_threshold):

                logger.error("circuit_breaker_opened",
                            name=self.name,
                            failure_count=self.failure_count,
                            failure_threshold=self.config.failure_threshold)
                self.state = CircuitState.OPEN

            elif self.state == CircuitState.HALF_OPEN:
                # If we fail in half-open, go back to open
                logger.warning("circuit_breaker_reopened",
                              name=self.name)
                self.state = CircuitState.OPEN
                self.success_count = 0

    def _should_record_failure(self, exception: Exception) -> bool:
        """Determine if exception should count as a circuit failure."""
        # Check if explicitly marked as success exception
        for exc_type in self.config.success_exceptions:
            if isinstance(exception, exc_type):
                return False

        # Check if explicitly marked as failure exception
        for exc_type in self.config.failure_exceptions:
            if isinstance(exception, exc_type):
                return True

        # Default: count as failure for any APIError
        return isinstance(exception, APIError)

    def get_status(self) -> Dict[str, Any]:
        """Get current circuit breaker status."""
        return {
            'name': self.name,
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'total_requests': self.total_requests,
            'total_successes': self.total_successes,
            'total_failures': self.total_failures,
            'last_failure_time': self.last_failure_time,
            'last_success_time': self.last_success_time,
            'failure_rate': self.total_failures / max(self.total_requests, 1),
        }

    async def reset(self):
        """Manually reset the circuit breaker."""
        async with self._lock:
            logger.info("circuit_breaker_manual_reset", name=self.name)
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.success_count = 0

    async def force_open(self):
        """Manually open the circuit breaker."""
        async with self._lock:
            logger.warning("circuit_breaker_manual_open", name=self.name)
            self.state = CircuitState.OPEN


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers."""

    def __init__(self):
        self.breakers: Dict[str, CircuitBreaker] = {}

    def get_breaker(self, name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """Get or create a circuit breaker."""
        if name not in self.breakers:
            config = config or CircuitBreakerConfig()
            self.breakers[name] = CircuitBreaker(name, config)

        return self.breakers[name]

    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all circuit breakers."""
        return {name: breaker.get_status() for name, breaker in self.breakers.items()}

    async def reset_all(self):
        """Reset all circuit breakers."""
        for breaker in self.breakers.values():
            await breaker.reset()


# Global registry instance
_registry = CircuitBreakerRegistry()


def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get a circuit breaker from the global registry."""
    return _registry.get_breaker(name, config)


def get_all_circuit_breakers_status() -> Dict[str, Dict[str, Any]]:
    """Get status of all registered circuit breakers."""
    return _registry.get_all_status()


async def reset_all_circuit_breakers():
    """Reset all circuit breakers."""
    await _registry.reset_all()


# Pre-configured circuit breakers for common services
def get_polymarket_circuit_breaker() -> CircuitBreaker:
    """Get circuit breaker configured for Polymarket API."""
    config = CircuitBreakerConfig(
        failure_threshold=3,    # Open after 3 failures
        success_threshold=2,    # Close after 2 successes
        timeout=30.0,          # Wait 30s before half-open
        reset_timeout=300.0,   # Reset failure count after 5m
    )
    return get_circuit_breaker("polymarket_api", config)


def get_telegram_circuit_breaker() -> CircuitBreaker:
    """Get circuit breaker configured for Telegram API."""
    config = CircuitBreakerConfig(
        failure_threshold=2,    # Open after 2 failures
        success_threshold=1,    # Close after 1 success
        timeout=60.0,          # Wait 60s before half-open
        reset_timeout=600.0,   # Reset failure count after 10m
    )
    return get_circuit_breaker("telegram_api", config)