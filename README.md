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

# Test validation and schemas
python3 -c "from src.validation import validate_wallet_address; print('✅ Validation works:', validate_wallet_address('0x742dE5a9b5fc17a187B86EC36B7b49B1B9F90a4f'))"

# Test detection signals
python3 -m src.detection.signals

# Test database
python3 -m src.storage.database

# Test Telegram alerts (shows preview if not configured)
python3 -m src.alerts.telegram

# Test circuit breaker
python3 -c "from src.circuit_breaker import get_polymarket_circuit_breaker; print('✅ Circuit breaker ready:', get_polymarket_circuit_breaker().get_status())"
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
│   ├── validation.py        # 🔒 Input validation & sanitization
│   ├── schemas.py           # 🔒 Pydantic schemas for API data
│   ├── exceptions.py        # 🔒 Specific error types
│   ├── circuit_breaker.py   # 🔒 Circuit breaker for API failures
│   ├── graceful_degradation.py # 🔒 Fallback mechanisms
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

## 🔒 Security Features

The application includes comprehensive security measures:

### Input Validation
- **Wallet addresses**: Strict Ethereum format validation (`0x[a-fA-F0-9]{40}`)
- **Market IDs**: Token ID format validation with type safety
- **Numeric data**: Decimal precision validation for prices/volumes
- **API responses**: Automatic sanitization removing dangerous keys and scripts

### Error Handling & Resilience
- **Specific exceptions**: Detailed error types instead of generic exceptions
- **Circuit breakers**: Automatic API failure protection with configurable thresholds
- **Graceful degradation**: Fallback mechanisms when external services fail
- **Retry logic**: Exponential backoff for transient failures

### Data Protection
- **Schema validation**: All external data validated via Pydantic schemas before use
- **Type safety**: Comprehensive type hints and runtime validation
- **Logging security**: Structured logging without sensitive data exposure

### API Security
- **Rate limiting**: Built-in protection against API abuse
- **Authentication**: Secure L1+L2 Polymarket API authentication
- **Timeout handling**: Prevents hanging requests
- **Connection pooling**: Efficient resource management

### Operational Security
- **Service monitoring**: Circuit breaker status and health metrics
- **Degraded mode operation**: Continue working with cached/limited data
- **Configuration validation**: Settings validated at startup
- **Error boundary isolation**: Component failures don't cascade

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

### ✅ Completed (Phase 1-2 + Security)

**Core Functionality:**
- [x] Project structure and imports
- [x] Configuration management with Pydantic Settings
- [x] Polymarket API client with L1+L2 authentication
- [x] Database schema and operations
- [x] All 5 detection signals
- [x] Telegram alerting system
- [x] Main orchestration loop

**🔒 Security Layer (Phase 1 Critical Security):**
- [x] Input validation layer (wallet addresses, market IDs, numeric data)
- [x] Pydantic schemas for all external API data validation
- [x] Specific error types replacing generic exceptions
- [x] Circuit breaker pattern for API failure protection
- [x] Graceful degradation with fallback mechanisms
- [x] API response sanitization (XSS/injection protection)

### 🚧 Priority Next Steps

**✅ Phase 2 Security (Completed):**
- [x] **Secrets Management**: Encrypted storage with password protection
- [x] **Rate Limiting**: Token bucket and sliding window algorithms
- [x] **Logging Security**: Automatic sensitive data redaction
- [x] **Error Response Sanitization**: Safe user-facing error messages

**✅ Phase 3 Security (Completed):**
- [x] **Database Security**: Field-level encryption for sensitive data
- [x] **API Input Rate Limiting**: IP-based abuse protection
- [x] **Monitoring & Alerting**: Real-time security event detection
- [x] **Configuration Validation**: Comprehensive startup validation

**🔵 Feature Development (Ready):**
- [ ] Wallet clustering (detect coordinated activity)
- [ ] Historical backtesting engine
- [ ] Performance tracking automation
- [ ] Web dashboard with authentication
- [ ] Docker deployment with security scanning
- [ ] Advanced anomaly detection algorithms
- [ ] Machine learning for pattern recognition

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
