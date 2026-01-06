"""
Security monitoring and alerting system.

Monitors security events, detects threats, and sends alerts for
suspicious activities, system anomalies, and security breaches.
"""

import asyncio
import time
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import structlog

from .secure_logging import get_secure_logger
from .circuit_breaker import get_all_circuit_breakers_status
from .rate_limiter import get_all_rate_limiter_stats
from .exceptions import TelegramSendError, ConfigurationError
from .alerts.telegram import TelegramNotifier

logger = get_secure_logger(__name__)


class SecurityEventLevel(Enum):
    """Security event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEventType(Enum):
    """Types of security events."""
    AUTHENTICATION_FAILURE = "auth_failure"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    API_ABUSE = "api_abuse"
    CONFIGURATION_ERROR = "config_error"
    SYSTEM_ANOMALY = "system_anomaly"
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"
    ENCRYPTION_ERROR = "encryption_error"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_BREACH_ATTEMPT = "data_breach_attempt"


@dataclass
class SecurityEvent:
    """Represents a security event."""
    event_type: SecurityEventType
    level: SecurityEventLevel
    title: str
    description: str
    source_component: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    affected_resources: List[str] = field(default_factory=list)
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_type": self.event_type.value,
            "level": self.level.value,
            "title": self.title,
            "description": self.description,
            "source_component": self.source_component,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "affected_resources": self.affected_resources,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent
        }

    def get_alert_priority(self) -> int:
        """Get numeric priority for alert ordering."""
        priority_map = {
            SecurityEventLevel.LOW: 1,
            SecurityEventLevel.MEDIUM: 2,
            SecurityEventLevel.HIGH: 3,
            SecurityEventLevel.CRITICAL: 4
        }
        return priority_map[self.level]


@dataclass
class MonitoringConfig:
    """Configuration for security monitoring."""

    # Alert thresholds
    max_auth_failures_per_hour: int = 10
    max_rate_limit_violations_per_hour: int = 50
    max_api_errors_per_hour: int = 100
    circuit_breaker_alert_threshold: int = 3  # Number of open breakers

    # Time windows
    event_aggregation_window_minutes: int = 5
    alert_cooldown_minutes: int = 15
    event_retention_hours: int = 24

    # Alert destinations
    enable_telegram_alerts: bool = True
    enable_log_alerts: bool = True
    alert_level_threshold: SecurityEventLevel = SecurityEventLevel.MEDIUM

    # System health monitoring
    monitor_circuit_breakers: bool = True
    monitor_rate_limiters: bool = True
    monitor_error_rates: bool = True
    monitor_response_times: bool = True

    # Anomaly detection
    enable_anomaly_detection: bool = True
    anomaly_detection_window_hours: int = 4
    anomaly_threshold_multiplier: float = 2.0


class SecurityEventAggregator:
    """Aggregates similar security events to reduce alert noise."""

    def __init__(self, window_minutes: int = 5):
        self.window_minutes = window_minutes
        self.events: Dict[str, List[SecurityEvent]] = defaultdict(list)

    def add_event(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """
        Add event and return aggregated event if threshold reached.

        Args:
            event: Security event to add

        Returns:
            Aggregated event if threshold reached, None otherwise
        """
        # Create aggregation key
        key = self._get_aggregation_key(event)

        # Clean old events outside window
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=self.window_minutes)
        self.events[key] = [
            e for e in self.events[key]
            if e.timestamp > cutoff_time
        ]

        # Add new event
        self.events[key].append(event)

        # Check if we should aggregate
        event_count = len(self.events[key])
        if event_count >= self._get_aggregation_threshold(event.event_type):
            # Create aggregated event
            aggregated = self._create_aggregated_event(self.events[key])

            # Clear events for this key
            self.events[key] = []

            return aggregated

        return None

    def _get_aggregation_key(self, event: SecurityEvent) -> str:
        """Generate aggregation key for similar events."""
        return f"{event.event_type.value}:{event.source_component}:{event.client_ip or 'unknown'}"

    def _get_aggregation_threshold(self, event_type: SecurityEventType) -> int:
        """Get aggregation threshold for event type."""
        thresholds = {
            SecurityEventType.AUTHENTICATION_FAILURE: 5,
            SecurityEventType.RATE_LIMIT_EXCEEDED: 10,
            SecurityEventType.API_ABUSE: 5,
            SecurityEventType.SUSPICIOUS_ACTIVITY: 3,
            SecurityEventType.SYSTEM_ANOMALY: 2,
        }
        return thresholds.get(event_type, 5)

    def _create_aggregated_event(self, events: List[SecurityEvent]) -> SecurityEvent:
        """Create aggregated event from multiple similar events."""
        first_event = events[0]
        latest_event = max(events, key=lambda e: e.timestamp)

        return SecurityEvent(
            event_type=first_event.event_type,
            level=SecurityEventLevel.HIGH,  # Escalate aggregated events
            title=f"Multiple {first_event.event_type.value} events",
            description=f"Detected {len(events)} similar security events in {self.window_minutes} minutes",
            source_component=first_event.source_component,
            timestamp=latest_event.timestamp,
            metadata={
                "event_count": len(events),
                "time_span_minutes": self.window_minutes,
                "first_event_time": first_event.timestamp.isoformat(),
                "last_event_time": latest_event.timestamp.isoformat(),
                "affected_ips": list(set(e.client_ip for e in events if e.client_ip))
            },
            affected_resources=list(set(
                resource
                for event in events
                for resource in event.affected_resources
            )),
            client_ip=first_event.client_ip
        )


class SecurityMonitor:
    """
    Main security monitoring system.

    Collects security events, detects patterns, and sends alerts
    for suspicious activities and system anomalies.
    """

    def __init__(self, config: Optional[MonitoringConfig] = None):
        self.config = config or MonitoringConfig()
        self.aggregator = SecurityEventAggregator(self.config.event_aggregation_window_minutes)

        # Event storage for analysis
        self.recent_events: deque = deque(maxlen=1000)
        self.alert_cooldowns: Dict[str, float] = {}  # Alert type -> last sent time

        # System metrics tracking
        self.metrics = {
            "events_processed": 0,
            "alerts_sent": 0,
            "events_aggregated": 0,
            "system_health_checks": 0
        }

        # Alert handlers
        self.alert_handlers: List[Callable[[SecurityEvent], None]] = []

        # Initialize Telegram notifier if enabled
        self.telegram_notifier: Optional[TelegramNotifier] = None
        if self.config.enable_telegram_alerts:
            try:
                self.telegram_notifier = TelegramNotifier()
            except Exception as e:
                logger.warning("telegram_notifier_init_failed", error=str(e))

        logger.info("security_monitor_initialized",
                   alert_threshold=self.config.alert_level_threshold.value,
                   telegram_enabled=self.config.enable_telegram_alerts)

    async def report_event(self, event: SecurityEvent) -> None:
        """
        Report a security event for monitoring.

        Args:
            event: SecurityEvent to report
        """
        self.metrics["events_processed"] += 1

        # Add to recent events
        self.recent_events.append(event)

        # Log the event
        logger.info("security_event_reported",
                   event_type=event.event_type.value,
                   level=event.level.value,
                   source=event.source_component,
                   title=event.title)

        # Check for aggregation
        aggregated_event = self.aggregator.add_event(event)
        if aggregated_event:
            self.metrics["events_aggregated"] += 1
            await self._send_alert(aggregated_event)
        elif event.level.value in [SecurityEventLevel.HIGH.value, SecurityEventLevel.CRITICAL.value]:
            # Send immediate alert for high/critical events
            await self._send_alert(event)

        # Run anomaly detection
        if self.config.enable_anomaly_detection:
            await self._detect_anomalies(event)

    async def _send_alert(self, event: SecurityEvent) -> None:
        """Send alert for security event."""
        if event.level.value < self.config.alert_level_threshold.value:
            return

        # Check alert cooldown
        cooldown_key = f"{event.event_type.value}:{event.source_component}"
        current_time = time.time()
        cooldown_seconds = self.config.alert_cooldown_minutes * 60

        if cooldown_key in self.alert_cooldowns:
            if current_time - self.alert_cooldowns[cooldown_key] < cooldown_seconds:
                logger.debug("alert_suppressed_cooldown",
                           event_type=event.event_type.value,
                           cooldown_remaining=cooldown_seconds - (current_time - self.alert_cooldowns[cooldown_key]))
                return

        self.alert_cooldowns[cooldown_key] = current_time

        # Send alerts through configured channels
        alert_tasks = []

        if self.config.enable_telegram_alerts and self.telegram_notifier:
            alert_tasks.append(self._send_telegram_alert(event))

        if self.config.enable_log_alerts:
            alert_tasks.append(self._send_log_alert(event))

        # Execute alert handlers
        for handler in self.alert_handlers:
            alert_tasks.append(self._execute_alert_handler(handler, event))

        # Send all alerts concurrently
        if alert_tasks:
            try:
                await asyncio.gather(*alert_tasks, return_exceptions=True)
                self.metrics["alerts_sent"] += 1
            except Exception as e:
                logger.error("alert_sending_failed", error=str(e))

    async def _send_telegram_alert(self, event: SecurityEvent) -> None:
        """Send security alert via Telegram."""
        try:
            alert_message = self._format_telegram_alert(event)
            await self.telegram_notifier.send_alert(
                alert_message,
                metadata={"security_event": True, "level": event.level.value}
            )
        except Exception as e:
            logger.error("telegram_security_alert_failed", error=str(e))

    async def _send_log_alert(self, event: SecurityEvent) -> None:
        """Send security alert via structured logs."""
        logger.critical("SECURITY_ALERT",
                       **event.to_dict(),
                       alert_sent=True)

    async def _execute_alert_handler(self, handler: Callable, event: SecurityEvent) -> None:
        """Execute custom alert handler."""
        try:
            if asyncio.iscoroutinefunction(handler):
                await handler(event)
            else:
                handler(event)
        except Exception as e:
            logger.error("alert_handler_failed",
                        handler=handler.__name__,
                        error=str(e))

    def _format_telegram_alert(self, event: SecurityEvent) -> str:
        """Format security event for Telegram alert."""
        level_emoji = {
            SecurityEventLevel.LOW: "🟡",
            SecurityEventLevel.MEDIUM: "🟠",
            SecurityEventLevel.HIGH: "🔴",
            SecurityEventLevel.CRITICAL: "🚨"
        }

        message = f"{level_emoji[event.level]} **SECURITY ALERT**\n\n"
        message += f"**Level:** {event.level.value.upper()}\n"
        message += f"**Type:** {event.event_type.value.replace('_', ' ').title()}\n"
        message += f"**Source:** {event.source_component}\n"
        message += f"**Time:** {event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        message += f"**Title:** {event.title}\n"
        message += f"**Description:** {event.description}\n"

        if event.client_ip:
            message += f"**Client IP:** {event.client_ip[:10]}***\n"

        if event.affected_resources:
            message += f"**Affected Resources:** {', '.join(event.affected_resources[:3])}\n"

        if event.metadata:
            message += f"\n**Additional Info:**\n"
            for key, value in list(event.metadata.items())[:3]:  # Limit to 3 items
                message += f"• {key}: {value}\n"

        message += f"\n**Event ID:** {event.event_type.value}-{int(event.timestamp.timestamp())}"

        return message

    async def _detect_anomalies(self, event: SecurityEvent) -> None:
        """Simple anomaly detection based on event patterns."""
        # Count events of this type in the detection window
        window_start = datetime.now(timezone.utc) - timedelta(hours=self.config.anomaly_detection_window_hours)

        similar_events = [
            e for e in self.recent_events
            if e.event_type == event.event_type and e.timestamp > window_start
        ]

        # Simple threshold-based anomaly detection
        if len(similar_events) >= 10:  # Arbitrary threshold
            # Calculate baseline (could be improved with historical data)
            baseline_count = 2  # Expected events per window
            current_count = len(similar_events)

            if current_count > baseline_count * self.config.anomaly_threshold_multiplier:
                anomaly_event = SecurityEvent(
                    event_type=SecurityEventType.SYSTEM_ANOMALY,
                    level=SecurityEventLevel.HIGH,
                    title=f"Anomalous {event.event_type.value} activity detected",
                    description=f"Detected {current_count} events (baseline: {baseline_count})",
                    source_component="security_monitor",
                    metadata={
                        "anomaly_type": "threshold_exceeded",
                        "current_count": current_count,
                        "baseline_count": baseline_count,
                        "threshold_multiplier": self.config.anomaly_threshold_multiplier,
                        "window_hours": self.config.anomaly_detection_window_hours
                    }
                )

                await self._send_alert(anomaly_event)

    async def monitor_system_health(self) -> None:
        """Monitor system health and generate alerts for issues."""
        self.metrics["system_health_checks"] += 1

        health_events = []

        # Monitor circuit breakers
        if self.config.monitor_circuit_breakers:
            cb_stats = get_all_circuit_breakers_status()
            open_breakers = [
                name for name, stats in cb_stats.items()
                if stats.get('state') == 'open'
            ]

            if len(open_breakers) >= self.config.circuit_breaker_alert_threshold:
                health_events.append(SecurityEvent(
                    event_type=SecurityEventType.CIRCUIT_BREAKER_OPEN,
                    level=SecurityEventLevel.HIGH,
                    title="Multiple circuit breakers open",
                    description=f"Detected {len(open_breakers)} open circuit breakers",
                    source_component="system_health",
                    metadata={"open_breakers": open_breakers},
                    affected_resources=open_breakers
                ))

        # Monitor rate limiters
        if self.config.monitor_rate_limiters:
            rl_stats = get_all_rate_limiter_stats()
            high_rejection_limiters = [
                name for name, stats in rl_stats.items()
                if stats.get('rejection_rate', 0) > 0.5  # 50% rejection rate
            ]

            if high_rejection_limiters:
                health_events.append(SecurityEvent(
                    event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                    level=SecurityEventLevel.MEDIUM,
                    title="High rate limiting activity",
                    description=f"Rate limiters with high rejection rates: {', '.join(high_rejection_limiters)}",
                    source_component="system_health",
                    metadata={"high_rejection_limiters": high_rejection_limiters}
                ))

        # Send health alerts
        for event in health_events:
            await self.report_event(event)

    def add_alert_handler(self, handler: Callable[[SecurityEvent], None]) -> None:
        """Add custom alert handler."""
        self.alert_handlers.append(handler)
        logger.info("alert_handler_added", handler=handler.__name__)

    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        return {
            **self.metrics,
            "recent_events_count": len(self.recent_events),
            "active_cooldowns": len(self.alert_cooldowns),
            "config": {
                "alert_threshold": self.config.alert_level_threshold.value,
                "aggregation_window": self.config.event_aggregation_window_minutes,
                "telegram_enabled": self.config.enable_telegram_alerts
            }
        }


# Global security monitor instance
_security_monitor: Optional[SecurityMonitor] = None


def get_security_monitor() -> SecurityMonitor:
    """Get or create global security monitor."""
    global _security_monitor
    if _security_monitor is None:
        _security_monitor = SecurityMonitor()
    return _security_monitor


async def report_security_event(event_type: SecurityEventType,
                               level: SecurityEventLevel,
                               title: str,
                               description: str,
                               source_component: str,
                               **kwargs) -> None:
    """Convenience function for reporting security events."""
    event = SecurityEvent(
        event_type=event_type,
        level=level,
        title=title,
        description=description,
        source_component=source_component,
        **kwargs
    )

    monitor = get_security_monitor()
    await monitor.report_event(event)


async def test_security_monitoring():
    """Test security monitoring functionality."""
    print("🔒 Testing Security Monitoring")
    print("=" * 35)

    monitor = SecurityMonitor()

    # Test different types of events
    test_events = [
        SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_FAILURE,
            level=SecurityEventLevel.MEDIUM,
            title="Failed login attempt",
            description="Invalid credentials provided",
            source_component="api_auth",
            client_ip="192.168.1.100"
        ),
        SecurityEvent(
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            level=SecurityEventLevel.HIGH,
            title="Rate limit exceeded",
            description="Client exceeded 100 requests per minute",
            source_component="api_gateway",
            client_ip="10.0.0.50"
        ),
        SecurityEvent(
            event_type=SecurityEventType.SUSPICIOUS_ACTIVITY,
            level=SecurityEventLevel.CRITICAL,
            title="Potential data breach attempt",
            description="Unauthorized access to sensitive endpoints",
            source_component="data_layer",
            affected_resources=["wallets", "alerts"]
        )
    ]

    for event in test_events:
        await monitor.report_event(event)
        print(f"✅ Reported: {event.title} ({event.level.value})")

    # Test system health monitoring
    await monitor.monitor_system_health()
    print("✅ System health check completed")

    # Show statistics
    stats = monitor.get_monitoring_stats()
    print(f"\nStatistics:")
    print(f"  Events processed: {stats['events_processed']}")
    print(f"  Alerts sent: {stats['alerts_sent']}")

    print("\n✅ Security monitoring test completed")


if __name__ == "__main__":
    asyncio.run(test_security_monitoring())