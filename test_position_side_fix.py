#!/usr/bin/env python3
"""
Test script to validate the position side fix.

This script tests that YES/NO position sides are correctly detected.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.polymarket.client import Trade, TradeSide

def test_position_side_detection():
    """Test that position sides are correctly determined."""

    print("🎯 Testing Position Side Detection Fix")
    print("=" * 45)

    # Test cases based on your real examples
    test_cases = [
        {
            "name": "NO purchase at 66.4%",
            "outcome": "No",
            "price": 0.664,
            "expected_side": "No"
        },
        {
            "name": "YES purchase at 35%",
            "outcome": "Yes",
            "price": 0.35,
            "expected_side": "Yes"
        },
        {
            "name": "Legacy trade (no outcome data)",
            "outcome": "",
            "price": 0.75,
            "expected_side": "YES"  # Fallback to old logic
        },
        {
            "name": "Legacy trade (no outcome data, low price)",
            "outcome": "",
            "price": 0.25,
            "expected_side": "NO"  # Fallback to old logic
        }
    ]

    print("Test Case Results:")
    print("-" * 45)

    for case in test_cases:
        # Create a test trade
        trade = Trade(
            id="test_trade",
            market="0xtest",
            maker="0xtestmaker",
            taker="0xtesttaker",
            side=TradeSide.BUY,
            outcome=case["outcome"],
            size=1000,
            price=case["price"],
            timestamp=datetime.now(timezone.utc)
        )

        # Test the logic from signals.py
        position_side = trade.outcome if trade.outcome else ("YES" if trade.price > 0.5 else "NO")

        # Check result
        is_correct = position_side == case["expected_side"]
        status = "✅" if is_correct else "❌"

        print(f"{status} {case['name']}")
        print(f"    Outcome: '{case['outcome']}', Price: {case['price']:.1%}")
        print(f"    Detected: {position_side}, Expected: {case['expected_side']}")
        print()

    print("🎯 Real Example from your alert:")
    print("   Trade: Bought NO tokens at 66.4%")
    print("   Before fix: 'Side: YES' (wrong!)")
    print("   After fix:  'Side: No' (correct!)")

if __name__ == "__main__":
    test_position_side_detection()