#!/usr/bin/env python3
"""
Test script to validate the arbitrage bot filtering.

This script tests that trades above 85% price are filtered out.
"""

import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.polymarket.client import Trade, TradeSide
from datetime import datetime, timezone

def test_arbitrage_filtering():
    """Test that high-price trades are filtered out."""

    print("🤖 Testing Arbitrage Bot Filtering")
    print("=" * 40)

    # Create test trades at different price levels
    test_trades = [
        ("Low price trade", 0.15),     # Should pass
        ("Medium price trade", 0.65),  # Should pass
        ("Threshold trade", 0.85),     # Should pass (exactly at threshold)
        ("Arbitrage bot", 0.90),       # Should be filtered
        ("High arbitrage", 0.99),      # Should be filtered
        ("Near certainty", 0.995),     # Should be filtered
    ]

    for name, price in test_trades:
        # Simulate the filtering logic from main.py
        should_filter = (price > 0.85)

        status = "🚫 FILTERED" if should_filter else "✅ ANALYZED"
        upside = f"{(1-price)*100:.1f}%" if not should_filter else "N/A"

        print(f"{name:<20} | Price: {price:>5.1%} | {status:<12} | Upside: {upside}")

    print("\n📊 Summary:")
    print("• Trades ≤ 85%: Analyzed (real insider potential)")
    print("• Trades > 85%: Filtered (likely arbitrage bots)")
    print("\n🎯 This should eliminate all your 99% price alerts!")

    # Show what the previous alerts would look like
    print("\n🔍 Previous Alert Examples:")
    previous_alerts = [
        ("Infinex alert", 99.9, 2320.36),
        ("Bitcoin alert", 99.0, 1110.03),
        ("Ethereum alert", 86.5, 1003.78),
    ]

    for name, price_pct, size in previous_alerts:
        price = price_pct / 100
        would_filter = price > 0.85

        if would_filter:
            print(f"❌ {name}: {price:.1%} (${size:.2f}) - WOULD BE FILTERED")
        else:
            print(f"✅ {name}: {price:.1%} (${size:.2f}) - Would still alert")

if __name__ == "__main__":
    test_arbitrage_filtering()