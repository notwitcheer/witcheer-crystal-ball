"""
Insider detection signals and analysis.
"""

from .signals import (
    InsiderDetector,
    WalletProfile,
    SuspicionReport,
    SignalResult,
    SignalType,
    FreshWalletDetector,
    UnusualSizingDetector,
    NicheMarketDetector,
    TimingPatternDetector,
    RepeatWinnerDetector,
)

__all__ = [
    "InsiderDetector",
    "WalletProfile",
    "SuspicionReport",
    "SignalResult",
    "SignalType",
    "FreshWalletDetector",
    "UnusualSizingDetector",
    "NicheMarketDetector",
    "TimingPatternDetector",
    "RepeatWinnerDetector",
]
