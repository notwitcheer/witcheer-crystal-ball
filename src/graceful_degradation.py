"""
Graceful degradation patterns for Witcher's Crystal Ball.

Provides fallback mechanisms and reduced functionality modes when
external dependencies fail, ensuring the system continues operating
even with degraded capabilities.
"""

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic
from functools import wraps
import structlog

from .exceptions import (
    CrystalBallError,
    APIError,
    PolymarketAPIError,
    TelegramError,
    DatabaseError,
    InsufficientDataError
)

logger = structlog.get_logger(__name__)

T = TypeVar('T')


class ServiceState(Enum):
    """Service availability states."""
    FULL = "full"                    # All features available
    DEGRADED = "degraded"           # Reduced functionality
    MINIMAL = "minimal"             # Basic functionality only
    UNAVAILABLE = "unavailable"    # Service not available


@dataclass
class FallbackConfig:
    """Configuration for fallback behavior."""

    # Retry configuration
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    backoff_multiplier: float = 2.0

    # Timeout configuration
    timeout: float = 30.0

    # Whether to use cached data as fallback
    use_cache: bool = True
    cache_max_age: float = 300.0  # 5 minutes

    # Minimum service level to maintain
    min_service_level: ServiceState = ServiceState.MINIMAL


class GracefulDegradationMixin:
    """Mixin class for adding graceful degradation to services."""

    def __init__(self):
        self.service_state = ServiceState.FULL
        self.degradation_reason: Optional[str] = None
        self.last_degradation_time: Optional[float] = None
        self._service_cache: Dict[str, Any] = {}

    def set_service_state(self, state: ServiceState, reason: Optional[str] = None):
        """Update service state with optional reason."""
        if self.service_state != state:
            logger.warning(
                "service_state_changed",
                service=self.__class__.__name__,
                old_state=self.service_state.value,
                new_state=state.value,
                reason=reason
            )

        self.service_state = state
        self.degradation_reason = reason
        self.last_degradation_time = asyncio.get_event_loop().time()

    def is_service_available(self, required_level: ServiceState = ServiceState.MINIMAL) -> bool:
        """Check if service is available at the required level."""
        state_priority = {
            ServiceState.UNAVAILABLE: 0,
            ServiceState.MINIMAL: 1,
            ServiceState.DEGRADED: 2,
            ServiceState.FULL: 3
        }

        return state_priority[self.service_state] >= state_priority[required_level]

    def get_service_status(self) -> Dict[str, Any]:
        """Get current service status information."""
        return {
            'service': self.__class__.__name__,
            'state': self.service_state.value,
            'reason': self.degradation_reason,
            'degradation_time': self.last_degradation_time,
            'cache_size': len(self._service_cache)
        }


def with_fallback(fallback_func: Optional[Callable] = None,
                 config: Optional[FallbackConfig] = None):
    """
    Decorator for adding fallback behavior to functions.

    Usage:
        @with_fallback(fallback_func=get_cached_data)
        async def get_api_data():
            return await api_call()
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            fallback_config = config or FallbackConfig()

            # Try main function with retries
            for attempt in range(fallback_config.max_retries + 1):
                try:
                    if asyncio.iscoroutinefunction(func):
                        result = await asyncio.wait_for(
                            func(*args, **kwargs),
                            timeout=fallback_config.timeout
                        )
                    else:
                        result = func(*args, **kwargs)

                    logger.debug("function_success",
                               function=func.__name__,
                               attempt=attempt + 1)
                    return result

                except Exception as e:
                    logger.warning("function_attempt_failed",
                                 function=func.__name__,
                                 attempt=attempt + 1,
                                 max_attempts=fallback_config.max_retries + 1,
                                 error=str(e))

                    # If this is the last attempt or we shouldn't retry
                    if attempt == fallback_config.max_retries:
                        break

                    # Calculate delay with exponential backoff
                    delay = min(
                        fallback_config.base_delay * (fallback_config.backoff_multiplier ** attempt),
                        fallback_config.max_delay
                    )
                    await asyncio.sleep(delay)

            # Try fallback function if available
            if fallback_func:
                try:
                    logger.info("attempting_fallback",
                               function=func.__name__,
                               fallback=fallback_func.__name__)

                    if asyncio.iscoroutinefunction(fallback_func):
                        return await fallback_func(*args, **kwargs)
                    else:
                        return fallback_func(*args, **kwargs)

                except Exception as e:
                    logger.error("fallback_failed",
                               function=func.__name__,
                               fallback=fallback_func.__name__,
                               error=str(e))

            # If we get here, both main and fallback failed
            logger.error("all_attempts_failed", function=func.__name__)
            raise CrystalBallError(f"Function {func.__name__} failed after all retry attempts and fallback")

        return wrapper

    return decorator


class CachedDataProvider(Generic[T]):
    """Provides cached data as fallback when live data is unavailable."""

    def __init__(self, cache_key: str, max_age: float = 300.0):
        self.cache_key = cache_key
        self.max_age = max_age
        self._cache: Dict[str, Dict[str, Any]] = {}

    def store(self, data: T) -> None:
        """Store data in cache with timestamp."""
        self._cache[self.cache_key] = {
            'data': data,
            'timestamp': asyncio.get_event_loop().time()
        }

        logger.debug("cache_stored", key=self.cache_key, data_type=type(data).__name__)

    def get(self) -> Optional[T]:
        """Get cached data if not expired."""
        if self.cache_key not in self._cache:
            return None

        cache_entry = self._cache[self.cache_key]
        current_time = asyncio.get_event_loop().time()

        if current_time - cache_entry['timestamp'] > self.max_age:
            logger.debug("cache_expired", key=self.cache_key)
            del self._cache[self.cache_key]
            return None

        logger.debug("cache_hit", key=self.cache_key)
        return cache_entry['data']

    def is_available(self) -> bool:
        """Check if cached data is available and not expired."""
        return self.get() is not None

    def clear(self) -> None:
        """Clear cached data."""
        if self.cache_key in self._cache:
            del self._cache[self.cache_key]


class DegradedMarketDataProvider:
    """Provides reduced market data functionality when APIs fail."""

    def __init__(self):
        self.market_cache = CachedDataProvider[List[Dict]]("markets", max_age=600.0)
        self.event_cache = CachedDataProvider[List[Dict]]("events", max_age=600.0)

    async def get_cached_markets(self, min_volume_usd: float = 1000.0) -> List[Dict[str, Any]]:
        """Get cached market data, filtered by minimum volume."""
        cached_markets = self.market_cache.get()

        if not cached_markets:
            logger.warning("no_cached_markets_available")
            return []

        # Filter by volume if data is available
        filtered_markets = []
        for market in cached_markets:
            try:
                volume = float(market.get('volume', 0))
                if volume >= min_volume_usd:
                    filtered_markets.append(market)
            except (ValueError, TypeError):
                # Include market if we can't parse volume
                filtered_markets.append(market)

        logger.info("degraded_markets_provided",
                   total_cached=len(cached_markets),
                   filtered_count=len(filtered_markets),
                   min_volume=min_volume_usd)

        return filtered_markets

    async def get_essential_market_data(self, market_id: str) -> Optional[Dict[str, Any]]:
        """Get essential market data from cache or generate minimal data."""
        cached_markets = self.market_cache.get()

        if cached_markets:
            # Find market in cache
            for market in cached_markets:
                if market.get('id') == market_id:
                    return market

        # Return minimal market data structure
        logger.info("providing_minimal_market_data", market_id=market_id)
        return {
            'id': market_id,
            'question': 'Unknown Market',
            'active': True,
            'volume': '0',
            'liquidity': '0',
            '_degraded': True
        }


class DegradedTelegramNotifier:
    """Provides reduced notification functionality when Telegram fails."""

    def __init__(self):
        self.failed_messages: List[Dict[str, Any]] = []
        self.max_failed_messages = 100

    async def queue_message(self, message: str, metadata: Optional[Dict] = None):
        """Queue message for later delivery when Telegram is available."""
        self.failed_messages.append({
            'message': message,
            'metadata': metadata or {},
            'timestamp': asyncio.get_event_loop().time()
        })

        # Limit queue size
        if len(self.failed_messages) > self.max_failed_messages:
            self.failed_messages.pop(0)

        logger.info("telegram_message_queued",
                   queue_size=len(self.failed_messages),
                   message_preview=message[:50])

    async def log_alert_as_fallback(self, alert_data: Dict[str, Any]):
        """Log alert data to structured logs as fallback notification."""
        logger.error("suspicious_activity_detected",
                    wallet_address=alert_data.get('wallet_address'),
                    market_id=alert_data.get('market_id'),
                    signal_type=alert_data.get('signal_type'),
                    suspicion_score=alert_data.get('suspicion_score'),
                    position_size_usd=alert_data.get('position_size_usd'),
                    fallback_notification=True)

    def get_queued_messages(self) -> List[Dict[str, Any]]:
        """Get all queued messages for batch delivery."""
        return self.failed_messages.copy()

    def clear_queue(self):
        """Clear the message queue after successful delivery."""
        cleared_count = len(self.failed_messages)
        self.failed_messages.clear()
        logger.info("telegram_queue_cleared", message_count=cleared_count)


class DegradedDetectionEngine:
    """Provides reduced detection capabilities when data sources fail."""

    def __init__(self):
        self.signal_weights = {
            'fresh_wallet': 30,      # Increased weight when fewer signals
            'unusual_sizing': 35,    # Increased weight
            'niche_concentration': 35,  # Increased weight
        }

    async def simple_fresh_wallet_detection(self, trades: List[Dict],
                                           threshold_days: int = 7) -> bool:
        """Simplified fresh wallet detection using available trade data."""
        if not trades:
            return False

        # Count unique trading days
        trade_dates = set()
        for trade in trades:
            try:
                # Simple date extraction (assume ISO format)
                timestamp = trade.get('timestamp', '')
                if timestamp:
                    date = timestamp.split('T')[0]  # Get date part
                    trade_dates.add(date)
            except Exception:
                continue

        # If we have trades spanning fewer than threshold days, might be fresh
        return len(trade_dates) <= threshold_days

    async def calculate_degraded_suspicion_score(self, wallet_address: str,
                                               available_signals: Dict[str, bool]) -> int:
        """Calculate suspicion score using only available signals."""
        total_score = 0
        active_signals = []

        for signal_name, is_triggered in available_signals.items():
            if signal_name in self.signal_weights and is_triggered:
                score = self.signal_weights[signal_name]
                total_score += score
                active_signals.append(signal_name)

        logger.info("degraded_scoring",
                   wallet_address=wallet_address,
                   available_signals=list(available_signals.keys()),
                   active_signals=active_signals,
                   total_score=total_score)

        return min(total_score, 100)  # Cap at 100


# Global instances for degraded services
degraded_market_provider = DegradedMarketDataProvider()
degraded_telegram_notifier = DegradedTelegramNotifier()
degraded_detection_engine = DegradedDetectionEngine()