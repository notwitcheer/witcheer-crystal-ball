# Witcher's Crystal Ball - Polymarket Insider Activity Detector

## Project Overview

A bot that tracks potential insider activity on Polymarket by monitoring suspicious wallet behavior patterns. The goal is to detect informed trading before markets react, giving us an edge on event outcomes.

### Core Thesis
Insiders can't hide their behavior completely. They leave traces:
- Fresh wallets making large, confident bets
- Unusual position sizing relative to market liquidity
- Repeated profitable entries in niche/low-volume markets
- Timing patterns (betting shortly before events resolve)

We don't predict the future - we track those who might already know it.

## Tech Stack

- **Language**: Python 3.11+
- **Database**: SQLite (local storage for wallet history and alerts)
- **Notifications**: Telegram Bot API (for real-time alerts)
- **Scheduling**: APScheduler or simple cron jobs
- **HTTP Client**: httpx (async support for API calls)

## Project Structure

```
witchers-crystal-ball/
├── src/
│   ├── __init__.py
│   ├── main.py              # Entry point, orchestrates monitoring
│   ├── polymarket/
│   │   ├── __init__.py
│   │   ├── client.py        # Polymarket API wrapper
│   │   ├── models.py        # Data classes for markets, positions, etc.
│   │   └── endpoints.py     # API endpoint constants
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── analyzer.py      # Core detection logic
│   │   ├── signals.py       # Individual signal detectors
│   │   └── scoring.py       # Suspicion score calculation
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py      # SQLite operations
│   │   └── models.py        # Database schema
│   ├── alerts/
│   │   ├── __init__.py
│   │   └── telegram.py      # Telegram notification handler
│   └── config.py            # Configuration management
├── data/
│   └── crystal_ball.db      # SQLite database
├── tests/
│   └── ...
├── .env                     # API keys, Telegram bot token
├── requirements.txt
└── README.md
```

## Polymarket API Information

### Base URLs
- **CLOB API** (order book, trades): `https://clob.polymarket.com`
- **Gamma API** (markets, events): `https://gamma-api.polymarket.com`

### Key Endpoints

```python
# Markets and Events
GET /events                    # List all events
GET /events/{event_id}         # Single event details
GET /markets                   # List all markets
GET /markets/{market_id}       # Single market details

# Trading Activity (CLOB)
GET /trades                    # Recent trades (supports filtering)
GET /orders                    # Order book data
GET /positions                 # Wallet positions (requires address param)

# Useful query params for /trades:
# - market: filter by market ID (token_id)
# - maker: filter by wallet address
# - limit: number of results
# - before/after: pagination cursors
```

### Rate Limits
- No official rate limit documentation, but be respectful
- Implement exponential backoff on 429 responses
- Cache market metadata (doesn't change often)

## Detection Signals

### Signal 1: Fresh Wallet Detection
```python
# A wallet is "fresh" if:
# - First seen on Polymarket within last 7 days
# - Has fewer than 5 total historical trades
# - Making a position > $500 in a single market

FRESH_WALLET_THRESHOLD_DAYS = 7
FRESH_WALLET_MIN_TRADES = 5
FRESH_WALLET_POSITION_THRESHOLD = 500  # USD
```

### Signal 2: Unusual Position Sizing
```python
# Flag when:
# - Position size > 5% of total market liquidity
# - Position size > 3x the median position in that market
# - Single trade represents > 10% of 24h volume

LIQUIDITY_THRESHOLD_PCT = 0.05
MEDIAN_MULTIPLIER = 3
VOLUME_THRESHOLD_PCT = 0.10
```

### Signal 3: Niche Market Concentration
```python
# Flag when:
# - Market has < $50k total volume
# - Wallet takes > 20% of one side
# - Event resolves within 72 hours

NICHE_MARKET_VOLUME_THRESHOLD = 50000
POSITION_DOMINANCE_THRESHOLD = 0.20
RESOLUTION_WINDOW_HOURS = 72
```

### Signal 4: Timing Patterns
```python
# Flag when:
# - Large position opened < 24h before resolution
# - Wallet has history of "last minute" winning bets
# - Multiple wallets show coordinated timing

LAST_MINUTE_THRESHOLD_HOURS = 24
COORDINATION_TIME_WINDOW_MINUTES = 30
```

### Suspicion Scoring
```python
# Each signal contributes to a total score (0-100)
# Alert threshold: 60+

SIGNAL_WEIGHTS = {
    "fresh_wallet": 25,
    "unusual_sizing": 20,
    "niche_concentration": 25,
    "timing_pattern": 20,
    "repeat_winner": 10,  # Historical accuracy of wallet
}
```

## Database Schema

```sql
-- Track all observed wallets
CREATE TABLE wallets (
    address TEXT PRIMARY KEY,
    first_seen TIMESTAMP,
    total_trades INTEGER DEFAULT 0,
    total_volume_usd REAL DEFAULT 0,
    win_rate REAL,  -- NULL until sufficient history
    last_updated TIMESTAMP
);

-- Track suspicious activity alerts
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wallet_address TEXT,
    market_id TEXT,
    event_slug TEXT,
    signal_type TEXT,
    suspicion_score INTEGER,
    position_size_usd REAL,
    position_side TEXT,  -- 'YES' or 'NO'
    price_at_detection REAL,
    created_at TIMESTAMP,
    resolved_at TIMESTAMP,
    outcome TEXT,  -- 'WIN', 'LOSS', or NULL if pending
    FOREIGN KEY (wallet_address) REFERENCES wallets(address)
);

-- Track our performance
CREATE TABLE performance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER,
    entry_price REAL,
    exit_price REAL,
    pnl_usd REAL,
    notes TEXT,
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);
```

## Alert Format (Telegram)

```
🔮 CRYSTAL BALL ALERT

⚠️ Suspicion Score: 78/100

📊 Market: Will X happen by Y date?
🏷️ Event: [event-slug]

👛 Wallet: 0x1234...5678
   • First seen: 2 days ago
   • Total trades: 3
   • Win rate: Unknown

💰 Position:
   • Side: YES
   • Size: $2,450
   • Price: $0.075
   • % of market: 8.2%

🚨 Signals Triggered:
   ✓ Fresh wallet (25pts)
   ✓ Unusual sizing (20pts)
   ✓ Niche market (25pts)
   ✗ Timing pattern
   ✗ Repeat winner

🔗 Market: [polymarket link]
🔗 Wallet: [polygonscan link]
```

## Configuration (.env)

```env
# Telegram
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Monitoring
SCAN_INTERVAL_SECONDS=60
ALERT_THRESHOLD_SCORE=60

# Filters (comma-separated market IDs to ignore)
IGNORED_MARKETS=

# Database
DATABASE_PATH=data/crystal_ball.db
```

## Development Guidelines

### Code Style
- Use type hints everywhere
- Write docstrings explaining the "why", not just the "what"
- Keep functions small and focused (< 30 lines ideally)
- Use dataclasses or Pydantic for data structures

### Error Handling
- Never crash on API errors - log and continue
- Implement circuit breaker for repeated failures
- Store failed requests for retry

### Logging
- Use structured logging (JSON format)
- Log levels: DEBUG for API calls, INFO for alerts, WARNING for anomalies
- Include wallet addresses and market IDs in log context

### Testing
- Unit tests for detection logic (mock API responses)
- Integration tests against live API (rate-limited)
- Backtest detection signals against historical data

## MVP Milestones

### Phase 1: Foundation
- [ ] Polymarket API client with basic endpoints
- [ ] SQLite database setup
- [ ] Wallet tracking (first_seen, trade count)

### Phase 2: Detection
- [ ] Fresh wallet signal
- [ ] Unusual sizing signal
- [ ] Basic suspicion scoring

### Phase 3: Alerts
- [ ] Telegram bot setup
- [ ] Alert formatting and sending
- [ ] Basic filtering (ignore high-volume markets)

### Phase 4: Refinement
- [ ] Niche market detection
- [ ] Timing pattern analysis
- [ ] Performance tracking (did alerts lead to wins?)

### Phase 5: Advanced
- [ ] Wallet clustering (detect coordinated activity)
- [ ] Historical backtesting
- [ ] Web dashboard for reviewing alerts

## Important Notes

- This is for RESEARCH and EDUCATIONAL purposes
- Never risk more than you can afford to lose
- Insider signals are not guarantees - they're probabilistic edges
- Track your performance honestly to refine the model

## Useful Resources

- Polymarket API Docs: https://docs.polymarket.com
- Polymarket GitHub: https://github.com/Polymarket
- CLOB Client SDK: https://github.com/Polymarket/py-clob-client
