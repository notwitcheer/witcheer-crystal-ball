"""
Web dashboard module for Witcher's Crystal Ball monitoring interface.

Provides secure web interface for viewing alerts, performance metrics,
wallet analysis, and system status with role-based authentication.
"""

from .app import (
    CrystalBallDashboard,
    DashboardAuth,
    DashboardUser,
    AlertSummary,
    PerformanceSummary,
    create_dashboard_app
)

__all__ = [
    "CrystalBallDashboard",
    "DashboardAuth",
    "DashboardUser",
    "AlertSummary",
    "PerformanceSummary",
    "create_dashboard_app"
]