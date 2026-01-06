# Witcher's Crystal Ball - Polymarket Insider Activity Detector

A bot that tracks potential insider activity on Polymarket by monitoring suspicious wallet behavior patterns. Detects informed trading before markets react, giving you an edge on event outcomes.

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd witcheer-crystal-ball

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your Telegram credentials (optional but recommended)
nano .env
```

### 3. Run Tests

Test individual components:

```bash
# Test configuration
python3 -m src.config

# Test detection signals
python3 -m src.detection.signals

# Test database
python3 -m src.storage.database

# Test Telegram alerts (shows preview if not configured)
python3 -m src.alerts.telegram
```

### 4. Run the Bot

```bash
# Single scan (test mode)
python3 -m src.main --single

# Continuous monitoring
python3 -m src.main

# With debug logging
python3 -m src.main --debug
```

## Project Structure

```
witcheer-crystal-ball/
├── src/
│   ├── __init__.py
│   ├── main.py              # Entry point, orchestrates monitoring
│   ├── config.py            # Configuration management
│   ├── polymarket/          # Polymarket API client
│   │   ├── __init__.py
│   │   └── client.py
│   ├── detection/           # Insider detection logic
│   │   ├── __init__.py
│   │   └── signals.py
│   ├── storage/             # Database operations
│   │   ├── __init__.py
│   │   └── database.py
│   └── alerts/              # Notification system
│       ├── __init__.py
│       └── telegram.py
├── data/                    # SQLite database storage
├── .env.example             # Environment configuration template
├── requirements.txt         # Python dependencies
├── CLAUDE.md               # Detailed project documentation
└── README.md               # This file
```

## How It Works

The bot monitors Polymarket trades in real-time and flags suspicious patterns:

### Detection Signals

1. **Fresh Wallet** (25 pts)
   - New wallet making large bets
   - Less than 7 days old, fewer than 5 trades
   - Position size > $500

2. **Unusual Sizing** (20 pts)
   - Position > 5% of market liquidity
   - Trade > 10% of 24h volume
   - 3x larger than median position

3. **Niche Market Concentration** (25 pts)
   - Low-volume market (< $50k)
   - Wallet dominates one side (> 20%)
   - Resolves within 72 hours

4. **Timing Pattern** (20 pts)
   - Large position within 24h of resolution
   - History of last-minute winning bets

5. **Repeat Winner** (10 pts)
   - Win rate > 65% (suspicious accuracy)
   - Minimum 3 resolved trades

### Alert Threshold

- Alerts trigger when combined score ≥ 60/100
- Sent via Telegram with full context
- All activity logged to SQLite database

## Configuration

Key settings in `.env`:

```env
# Telegram (get from @BotFather)
TELEGRAM_BOT_TOKEN=your_token
TELEGRAM_CHAT_ID=your_chat_id

# Monitoring
SCAN_INTERVAL_SECONDS=60        # How often to scan
ALERT_THRESHOLD_SCORE=60        # Minimum score to alert

# Filtering
MIN_MARKET_VOLUME_USD=1000      # Ignore small markets
```

See `.env.example` for all available options.

## Database

SQLite database at `data/crystal_ball.db` tracks:

- **Wallets**: All observed addresses with stats
- **Alerts**: Suspicious activity detections
- **Performance**: Outcomes of alerts we followed

Query examples:

```python
from src.storage import Database

async with Database() as db:
    # Get recent alerts
    alerts = await db.get_recent_alerts(hours=24, min_score=70)

    # Check wallet history
    wallet = await db.get_wallet("0x...")

    # Performance stats
    stats = await db.get_performance_summary()
```

## Development Status

### ✅ Completed (Phase 1-2)

- [x] Project structure and imports
- [x] Configuration management
- [x] Polymarket API client
- [x] Database schema and operations
- [x] All 5 detection signals
- [x] Telegram alerting system
- [x] Main orchestration loop

### 🚧 To Do (Phase 3-5)

- [ ] API authentication (currently 401 on some endpoints)
- [ ] Wallet clustering (detect coordinated activity)
- [ ] Historical backtesting
- [ ] Performance tracking automation
- [ ] Web dashboard
- [ ] Docker deployment

## Notes

- **Research/Educational Purpose**: This is for learning about market microstructure
- **No Guarantees**: Insider signals are probabilistic, not certain
- **Track Performance**: Honestly evaluate if alerts lead to profits
- **Be Respectful**: Rate limiting prevents API abuse

## Resources

- [Polymarket API Docs](https://docs.polymarket.com)
- [Polymarket GitHub](https://github.com/Polymarket)
- [CLOB Client SDK](https://github.com/Polymarket/py-clob-client)

---

**Disclaimer**: This tool is for research and educational purposes. Never risk more than you can afford to lose. Past performance doesn't guarantee future results.
