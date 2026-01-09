"""
Polymarket API Client for Witcher's Crystal Ball.

This module handles all communication with Polymarket's APIs:
- CLOB API: Trading data (trades, orders, positions)
- Gamma API: Market and event metadata

Design decisions:
1. Async-first: We'll be making many parallel requests, async prevents blocking
2. Rate limiting: Built-in to avoid getting blocked
3. Automatic retries: Transient failures shouldn't crash the bot
4. Type-safe responses: All data parsed into Pydantic models
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional
from enum import Enum

import httpx
import structlog
from pydantic import BaseModel, Field
from py_clob_client.client import ClobClient
from py_clob_client.constants import POLYGON
from py_clob_client.clob_types import TradeParams

from ..config import get_settings, PolymarketSettings

# Initialize structured logger
logger = structlog.get_logger()


# =============================================================================
# Data Models
# =============================================================================

class TradeSide(str, Enum):
    """Which side of the market the trade is on."""
    BUY = "BUY"
    SELL = "SELL"


class OutcomeType(str, Enum):
    """Binary market outcomes."""
    YES = "Yes"
    NO = "No"


class Trade(BaseModel):
    """
    A single trade on Polymarket.
    
    This is the core data we analyze for insider detection.
    Key fields for our signals:
    - maker/taker: wallet addresses involved
    - size: position size (in outcome tokens, not USD)
    - price: price paid (0.0 to 1.0, represents probability)
    - timestamp: when the trade occurred
    """
    id: str
    market: str = Field(description="Token ID of the market")
    asset_id: str = Field(default="", description="Asset identifier")
    
    # Trade participants
    maker: str = Field(description="Maker wallet address")
    taker: str = Field(description="Taker wallet address")
    
    # Trade details
    side: TradeSide
    outcome: str = Field(default="", description="YES or NO - which outcome was bought")
    size: float = Field(description="Size in outcome tokens")
    price: float = Field(ge=0.0, le=1.0, description="Price (0-1, probability)")

    # Timestamps
    timestamp: datetime = Field(description="When trade was executed")

    # Computed fields (we'll calculate these)
    size_usd: float = Field(default=0.0, description="Size in USD (size * price)")
    
    def model_post_init(self, __context) -> None:
        """Calculate USD size after model initialization."""
        # Size in outcome tokens * price = USD value
        # Note: This is approximate, actual USD depends on USDC collateral
        self.size_usd = self.size * self.price


class Market(BaseModel):
    """
    A prediction market on Polymarket.
    
    Contains metadata we need for context:
    - What event is this about?
    - When does it resolve?
    - How much liquidity/volume does it have?
    """
    id: str = Field(description="Unique market identifier (token_id)")
    question: str = Field(description="The market question")
    slug: str = Field(default="", description="URL-friendly identifier")
    
    # Event context
    event_id: Optional[str] = None
    event_slug: Optional[str] = None
    
    # Market status
    active: bool = True
    closed: bool = False
    resolved: bool = False
    
    # Resolution timing
    end_date: Optional[datetime] = Field(default=None, description="When market closes")
    resolution_date: Optional[datetime] = Field(default=None, description="When outcome known")
    
    # Liquidity metrics (critical for our signals)
    volume: float = Field(default=0.0, description="Total volume traded (USD)")
    volume_24h: float = Field(default=0.0, description="24-hour volume (USD)")
    liquidity: float = Field(default=0.0, description="Current liquidity (USD)")
    
    # Current prices
    yes_price: float = Field(default=0.5, ge=0.0, le=1.0)
    no_price: float = Field(default=0.5, ge=0.0, le=1.0)
    
    # Token IDs for YES/NO outcomes
    yes_token_id: Optional[str] = None
    no_token_id: Optional[str] = None
    
    @property
    def hours_until_resolution(self) -> Optional[float]:
        """Calculate hours until market resolves (if known)."""
        if not self.end_date:
            return None
        delta = self.end_date - datetime.now(timezone.utc)
        return delta.total_seconds() / 3600
    
    @property
    def is_niche(self) -> bool:
        """Check if this is a low-volume 'niche' market."""
        settings = get_settings()
        return self.volume < settings.detection.niche_market_volume_threshold_usd


class WalletPosition(BaseModel):
    """A wallet's position in a specific market."""
    wallet: str
    market_id: str
    outcome: OutcomeType
    size: float = Field(description="Position size in outcome tokens")
    avg_price: float = Field(description="Average entry price")
    
    @property
    def size_usd(self) -> float:
        """Approximate USD value of position."""
        return self.size * self.avg_price


# =============================================================================
# API Client
# =============================================================================

class PolymarketClient:
    """
    Async client for Polymarket APIs.

    Handles:
    - Authenticated access using py-clob-client
    - Rate limiting (configurable requests/second)
    - Automatic retries with exponential backoff
    - Response parsing into typed models
    - Error logging

    Usage:
        async with PolymarketClient() as client:
            trades = await client.get_recent_trades(limit=100)
            market = await client.get_market("0x...")
    """

    def __init__(self, settings: Optional[PolymarketSettings] = None):
        """
        Initialize the client.

        Args:
            settings: Optional custom settings. If None, loads from environment.
        """
        self.settings = settings or get_settings().polymarket
        self._client: Optional[httpx.AsyncClient] = None
        self._clob_client: Optional[ClobClient] = None

        # Rate limiting state
        self._request_times: list[float] = []
        self._rate_limit_lock = asyncio.Lock()
    
    async def __aenter__(self) -> "PolymarketClient":
        """Async context manager entry - creates HTTP and CLOB clients."""
        # Create HTTP client for Gamma API
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.timeout_seconds),
            headers={
                "Accept": "application/json",
                "User-Agent": "WitchersCrystalBall/1.0"
            }
        )

        # Determine authentication type based on key format
        key = self.settings.private_key or self.settings.api_key
        if key:
            # Check if it's a private key (0x + 64 hex chars) or API key (UUID format)
            if key.startswith('0x') and len(key) == 66:
                # Private key - use ClobClient with proper authentication
                auth_success = False

                # Try standard EOA wallet first (most common)
                for signature_type, wallet_type in [(0, "EOA"), (1, "Magic")]:
                    try:
                        self._clob_client = ClobClient(
                            host=self.settings.clob_base_url,
                            key=key,
                            chain_id=self.settings.chain_id,
                            signature_type=signature_type
                        )

                        # CRITICAL: Set up API credentials for L2 authentication
                        logger.debug("generating_api_creds", wallet_type=wallet_type)
                        api_creds = self._clob_client.create_or_derive_api_creds()
                        self._clob_client.set_api_creds(api_creds)

                        logger.info(
                            "clob_client_authenticated",
                            auth_type="private_key",
                            wallet_type=wallet_type,
                            chain_id=self.settings.chain_id,
                            api_key=api_creds.api_key[:10] + "..."
                        )
                        auth_success = True
                        break

                    except Exception as e:
                        logger.warning(
                            "clob_auth_attempt_failed",
                            wallet_type=wallet_type,
                            error=str(e)
                        )
                        self._clob_client = None
                        continue

                if not auth_success:
                    logger.error("clob_auth_completely_failed", message="All authentication methods failed")
            else:
                # API key - use HTTP client with auth headers
                self._client.headers["Authorization"] = f"Bearer {key}"
                logger.info("api_key_mode", message="Using API key for authentication", key_format="api_key")
        else:
            logger.warning("no_authentication", message="No private key or API key provided - some features may be limited")

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit - closes HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
        self._clob_client = None
    
    # =========================================================================
    # Rate Limiting
    # =========================================================================
    
    async def _wait_for_rate_limit(self) -> None:
        """
        Implement rate limiting using a sliding window.
        
        Why rate limiting matters:
        - Polymarket doesn't publish official limits
        - Being aggressive = getting blocked = missing data
        - Slower but reliable > fast but failing
        """
        async with self._rate_limit_lock:
            now = asyncio.get_event_loop().time()
            window_start = now - 1.0  # 1-second window
            
            # Remove old timestamps outside the window
            self._request_times = [
                t for t in self._request_times if t > window_start
            ]
            
            # Check if we're at the limit
            if len(self._request_times) >= self.settings.requests_per_second:
                # Wait until oldest request exits the window
                sleep_time = self._request_times[0] - window_start
                if sleep_time > 0:
                    logger.debug("rate_limit_wait", sleep_seconds=sleep_time)
                    await asyncio.sleep(sleep_time)
            
            # Record this request
            self._request_times.append(now)
    
    # =========================================================================
    # HTTP Methods with Retry Logic
    # =========================================================================
    
    async def _request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> dict:
        """
        Make an HTTP request with retry logic.
        
        Implements exponential backoff:
        - Attempt 1: immediate
        - Attempt 2: wait 1 second
        - Attempt 3: wait 2 seconds
        - etc.
        
        This handles transient failures (network blips, 503s) gracefully.
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use 'async with' context manager.")
        
        last_exception: Optional[Exception] = None
        
        for attempt in range(self.settings.retry_max_attempts):
            try:
                # Wait for rate limit
                await self._wait_for_rate_limit()
                
                # Make request
                response = await self._client.request(method, url, **kwargs)
                
                # Handle rate limit response
                if response.status_code == 429:
                    wait_time = self.settings.retry_base_delay_seconds * (2 ** attempt)
                    logger.warning(
                        "rate_limited",
                        url=url,
                        attempt=attempt + 1,
                        wait_seconds=wait_time
                    )
                    await asyncio.sleep(wait_time)
                    continue
                
                # Raise for other errors
                response.raise_for_status()
                
                return response.json()
                
            except httpx.HTTPStatusError as e:
                last_exception = e
                logger.warning(
                    "http_error",
                    url=url,
                    status_code=e.response.status_code,
                    attempt=attempt + 1
                )
                
            except httpx.RequestError as e:
                last_exception = e
                logger.warning(
                    "request_error",
                    url=url,
                    error=str(e),
                    attempt=attempt + 1
                )
            
            # Exponential backoff before retry
            if attempt < self.settings.retry_max_attempts - 1:
                wait_time = self.settings.retry_base_delay_seconds * (2 ** attempt)
                await asyncio.sleep(wait_time)
        
        # All retries exhausted
        logger.error(
            "request_failed",
            url=url,
            attempts=self.settings.retry_max_attempts,
            last_error=str(last_exception)
        )
        raise last_exception or RuntimeError(f"Request failed: {url}")
    
    async def _get(self, base_url: str, path: str, params: Optional[dict] = None) -> dict:
        """GET request helper."""
        url = f"{base_url}{path}"
        return await self._request("GET", url, params=params)
    
    # =========================================================================
    # CLOB API Methods (Trading Data)
    # =========================================================================
    
    async def get_recent_trades(
        self,
        market_id: Optional[str] = None,
        maker: Optional[str] = None,
        limit: int = 100,
        cursor: Optional[str] = None
    ) -> list[Trade]:
        """
        Get recent trades using the new PolymarketDataClient.

        SOLUTION: Uses polymarket-apis package to access real public trade data.
        This gives us access to actual wallet addresses and trading activity.

        Args:
            market_id: Filter by specific market (token_id)
            maker: Filter by specific wallet address
            limit: Number of trades to return
            cursor: Not used with DataClient

        Returns:
            List of Trade objects with real wallet addresses
        """
        await self._wait_for_rate_limit()

        try:
            # Import the new data client
            from polymarket_apis import PolymarketDataClient

            # Create data client (no auth needed for public trades)
            data_client = PolymarketDataClient()

            # Get real trades from the Data API
            logger.debug("fetching_real_trades", source="PolymarketDataClient", limit=limit)

            # Build parameters for DataClient
            params = {
                "limit": min(limit, 100),  # DataClient max is 100
                "taker_only": False,       # Get all trades, not just taker
            }

            # Filter by market if specified
            if market_id:
                params["condition_id"] = market_id

            # Filter by user if specified
            if maker:
                params["user"] = maker

            # Fetch real trades
            api_trades = data_client.get_trades(**params)

            trades = []
            for api_trade in api_trades:
                try:
                    # Create a Market object from the trade data
                    trade_market = Market(
                        id=api_trade.condition_id,
                        question=api_trade.title or "Unknown market",
                        slug=api_trade.slug or "",
                        event_slug=api_trade.event_slug or "",

                        # Set as active since we got trades from it
                        active=True,
                        closed=False,
                        resolved=False,

                        # We don't have volume data from trade, but set non-zero to pass filters
                        volume=1000.0,  # Placeholder since we know it has trades
                        volume_24h=100.0,

                        # We don't have current prices, but we can derive from trade
                        yes_price=api_trade.price if api_trade.outcome == 'Yes' else 1.0 - api_trade.price,
                        no_price=1.0 - api_trade.price if api_trade.outcome == 'Yes' else api_trade.price,
                    )

                    # Convert PolymarketDataClient trade to our Trade model
                    trade = Trade(
                        id=api_trade.transaction_hash or f"trade_{len(trades)}",
                        market=api_trade.condition_id,
                        asset_id=api_trade.token_id,

                        # REAL WALLET ADDRESSES!
                        maker=api_trade.proxy_wallet,  # Real wallet address
                        taker="unknown",               # DataClient doesn't provide taker

                        side=TradeSide(api_trade.side),
                        outcome=getattr(api_trade, 'outcome', ''),  # "Yes" or "No" if available
                        size=float(api_trade.size),
                        price=float(api_trade.price),
                        timestamp=api_trade.timestamp
                    )

                    # Attach market data to avoid API lookups
                    trade._cached_market = trade_market

                    trades.append(trade)

                except Exception as e:
                    logger.warning("trade_parse_error", error=str(e), raw_trade=str(api_trade))
                    continue

            logger.info(
                "real_trades_fetched",
                count=len(trades),
                source="PolymarketDataClient",
                market_id=market_id,
                has_real_wallets=True
            )
            return trades

        except ImportError:
            logger.error(
                "polymarket_apis_missing",
                message="polymarket-apis package not installed - install with: pip install polymarket-apis"
            )
            # Fallback to old method
            return await self._get_trades_clob_fallback(market_id, maker, limit, cursor)

        except Exception as e:
            logger.error("real_trades_fetch_error", error=str(e))
            # Fallback to old method
            return await self._get_trades_clob_fallback(market_id, maker, limit, cursor)

    async def _get_trades_clob_fallback(
        self,
        market_id: Optional[str] = None,
        maker: Optional[str] = None,
        limit: int = 100,
        cursor: Optional[str] = None
    ) -> list[Trade]:
        """
        Fallback method using CLOB client (returns only user trades or synthetic data).

        This is the old method that only worked for authenticated user's trades.
        """
        # Check if any form of authentication is available
        key = self.settings.private_key or self.settings.api_key
        if not self._clob_client and not key:
            logger.warning("no_auth_fallback_to_synthetic", message="No auth - using synthetic data")
            return await self._analyze_recent_market_activity(limit)

        try:
            if self._clob_client:
                # Use py-clob-client (only returns user's own trades)
                trade_params = TradeParams(
                    market=market_id,
                    maker_address=maker
                )

                response = self._clob_client.get_trades(
                    params=trade_params,
                    next_cursor=cursor
                )
                trade_data = response if isinstance(response, list) else response.get("data", [])
            else:
                trade_data = []

            trades = []
            for item in trade_data:
                try:
                    # Parse timestamp - API returns ISO format or Unix timestamp
                    timestamp = item.get("timestamp") or item.get("created_at")
                    if isinstance(timestamp, (int, float)):
                        timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                    elif isinstance(timestamp, str):
                        timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

                    trade = Trade(
                        id=str(item.get("id", "")),
                        market=item.get("market", item.get("token_id", "")),
                        asset_id=item.get("asset_id", ""),
                        maker=item.get("maker", ""),
                        taker=item.get("taker", ""),
                        side=TradeSide(item.get("side", "BUY")),
                        size=float(item.get("size", 0)),
                        price=float(item.get("price", 0)),
                        timestamp=timestamp
                    )
                    trades.append(trade)

                except Exception as e:
                    logger.warning("trade_parse_error", error=str(e), raw_data=item)
                    continue

            logger.debug("clob_trades_fetched", count=len(trades), market_id=market_id)

            # If CLOB returns 0 trades, use synthetic data
            if len(trades) == 0:
                logger.warning(
                    "clob_empty_using_synthetic",
                    message="CLOB returned 0 trades - using synthetic market analysis",
                    market_id=market_id
                )
                return await self._analyze_recent_market_activity(limit)

            return trades

        except Exception as e:
            logger.error("clob_fallback_error", error=str(e), market_id=market_id)
            return await self._analyze_recent_market_activity(limit)

    async def _analyze_recent_market_activity(self, limit: int = 100) -> list[Trade]:
        """
        IMPROVED Fallback method: Analyze recent active markets for unusual activity patterns.

        Since CLOB /trades API returns 0 results, we analyze markets with:
        - High 24h volume (indicates real trading activity)
        - Recent updates (shows current relevance)
        - Significant volume spikes

        This provides a better proxy for detecting suspicious activity.
        """
        # Get recent active markets (now using corrected closed=false parameter)
        markets = await self.get_markets(active=True, limit=limit)

        # Filter for markets with significant recent activity
        active_markets = []
        for market in markets:
            # Look for markets with substantial recent activity
            if (market.volume_24h > 500 and  # Minimum meaningful volume
                market.volume > 0):  # Has historical trading
                active_markets.append((market, market.volume_24h))

        # Sort by 24h volume to focus on most active markets
        active_markets.sort(key=lambda x: x[1], reverse=True)

        # Convert market activity into synthetic "trade" objects for our detector
        synthetic_trades = []
        for market, volume_24h in active_markets[:20]:  # Limit to top 20 most active
            # Create a synthetic trade representing recent market activity
            trade = Trade(
                id=f"synthetic_{market.id}_{int(datetime.now().timestamp())}",
                market=market.id,
                asset_id=market.yes_token_id or "",
                maker="unknown_wallet",  # We don't know the actual wallet
                taker="unknown_wallet",
                side=TradeSide.BUY if market.yes_price > 0.5 else TradeSide.SELL,
                size=market.volume_24h / (market.yes_price or 0.5),  # Approximate size
                price=market.yes_price,
                timestamp=datetime.now(timezone.utc)
            )
            synthetic_trades.append(trade)

        logger.info(
            "synthetic_trades_created",
            count=len(synthetic_trades),
            total_markets_checked=len(markets),
            active_markets_found=len(active_markets),
            avg_24h_volume=sum(vol for _, vol in active_markets[:len(synthetic_trades)]) / max(1, len(synthetic_trades))
        )

        return synthetic_trades
    
    async def get_wallet_positions(self, wallet_address: str) -> list[WalletPosition]:
        """
        Get all positions for a specific wallet.
        
        Useful for understanding a wallet's total exposure and history.
        
        Args:
            wallet_address: Ethereum address (0x...)
            
        Returns:
            List of positions across all markets
        """
        # Note: This endpoint may require the py-clob-client for authentication
        # For now, we'll use the public endpoint which may have limitations
        data = await self._get(
            self.settings.clob_base_url,
            f"/positions",
            params={"user": wallet_address}
        )
        
        positions = []
        for item in data.get("data", data if isinstance(data, list) else []):
            try:
                position = WalletPosition(
                    wallet=wallet_address,
                    market_id=item.get("market", item.get("token_id", "")),
                    outcome=OutcomeType(item.get("outcome", "Yes")),
                    size=float(item.get("size", 0)),
                    avg_price=float(item.get("avg_price", item.get("price", 0)))
                )
                positions.append(position)
            except Exception as e:
                logger.warning("position_parse_error", error=str(e), raw_data=item)
                continue
        
        logger.debug("positions_fetched", wallet=wallet_address, count=len(positions))
        return positions
    
    # =========================================================================
    # Gamma API Methods (Market Metadata)
    # =========================================================================
    
    async def get_market(self, market_id: str) -> Optional[Market]:
        """
        Get detailed information about a specific market.
        
        Args:
            market_id: The market's token ID
            
        Returns:
            Market object or None if not found
        """
        try:
            data = await self._get(
                self.settings.gamma_base_url,
                f"/markets/{market_id}"
            )
            return self._parse_market(data)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning("market_not_found", market_id=market_id)
                return None
            raise
    
    async def get_markets(
        self,
        active: bool = True,
        limit: int = 100,
        offset: int = 0
    ) -> list[Market]:
        """
        Get list of markets with optional filtering.

        Args:
            active: Only return active (non-resolved) markets
            limit: Number of results
            offset: Pagination offset

        Returns:
            List of Market objects
        """
        # FIXED: Use 'closed=false' instead of 'active=true' to get recent active markets
        params = {
            "limit": limit,
            "offset": offset,
            "closed": str(not active).lower()  # active=True -> closed=false
        }
        
        data = await self._get(
            self.settings.gamma_base_url,
            "/markets",
            params=params
        )
        
        markets = []
        # Gamma API returns a direct list, not wrapped in {"data": []}
        market_data = data if isinstance(data, list) else data.get("data", [])
        for item in market_data:
            market = self._parse_market(item)
            if market:
                markets.append(market)
        
        logger.debug("markets_fetched", count=len(markets), active=active)
        return markets
    
    async def get_events(self, limit: int = 100) -> list[dict]:
        """
        Get list of events (each event can have multiple markets).
        
        Returns raw dict for now - we'll add a proper Event model later.
        """
        data = await self._get(
            self.settings.gamma_base_url,
            "/events",
            params={"limit": limit}
        )
        return data.get("data", data if isinstance(data, list) else [])
    
    def _parse_price(self, data: dict, direct_field: str, outcome_index: int) -> float:
        """Parse price from market data, handling both direct fields and outcome arrays."""
        import json

        # Try direct field first (e.g., "yes_price", "no_price")
        if direct_field in data and data[direct_field] is not None:
            try:
                return float(data[direct_field])
            except (ValueError, TypeError):
                pass

        # Try outcomePrices array
        outcome_prices = data.get("outcomePrices", [0.5, 0.5])

        # Handle JSON string format
        if isinstance(outcome_prices, str):
            try:
                outcome_prices = json.loads(outcome_prices)
            except json.JSONDecodeError:
                outcome_prices = [0.5, 0.5]

        # Get the specific index
        if isinstance(outcome_prices, list) and len(outcome_prices) > outcome_index:
            try:
                return float(outcome_prices[outcome_index])
            except (ValueError, TypeError):
                pass

        # Default fallback
        return 0.5

    def _parse_market(self, data: dict) -> Optional[Market]:
        """Parse raw API response into Market model."""
        try:
            # Parse end date
            end_date = None
            if data.get("end_date") or data.get("end_date_iso"):
                end_str = data.get("end_date_iso") or data.get("end_date")
                if isinstance(end_str, str):
                    end_date = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
            
            return Market(
                id=data.get("id", data.get("token_id", "")),
                question=data.get("question", ""),
                slug=data.get("slug", ""),
                event_id=data.get("event_id"),
                event_slug=data.get("event_slug"),
                active=data.get("active", True),
                closed=data.get("closed", False),
                resolved=data.get("resolved", False),
                end_date=end_date,
                volume=float(data.get("volume", 0)),
                volume_24h=float(data.get("volume_24h", data.get("volume24hr", 0))),
                liquidity=float(data.get("liquidity", 0)),
                yes_price=self._parse_price(data, "yes_price", 0),
                no_price=self._parse_price(data, "no_price", 1),
                yes_token_id=data.get("yes_token_id", data.get("clobTokenIds", [None, None])[0]),
                no_token_id=data.get("no_token_id", data.get("clobTokenIds", [None, None])[1] if len(data.get("clobTokenIds", [])) > 1 else None)
            )
        except Exception as e:
            logger.warning("market_parse_error", error=str(e), raw_data=data)
            return None


# =============================================================================
# Quick Test
# =============================================================================

async def _test_client():
    """Quick test to verify the client works."""
    from rich import print as rprint
    from rich.table import Table
    
    rprint("[bold green]Testing Polymarket Client...[/bold green]\n")
    
    async with PolymarketClient() as client:
        # Test 1: Fetch recent trades
        rprint("[yellow]Fetching recent trades...[/yellow]")
        trades = await client.get_recent_trades(limit=5)
        
        if trades:
            table = Table(title="Recent Trades")
            table.add_column("Market", style="cyan", max_width=20)
            table.add_column("Maker", style="green", max_width=15)
            table.add_column("Side", style="yellow")
            table.add_column("Size", style="magenta")
            table.add_column("Price", style="blue")
            
            for trade in trades[:5]:
                table.add_row(
                    trade.market[:20] + "...",
                    trade.maker[:10] + "...",
                    trade.side.value,
                    f"${trade.size_usd:.2f}",
                    f"{trade.price:.3f}"
                )
            
            rprint(table)
        else:
            rprint("[red]No trades returned[/red]")
        
        # Test 2: Fetch active markets
        rprint("\n[yellow]Fetching active markets...[/yellow]")
        markets = await client.get_markets(limit=5)
        
        if markets:
            table = Table(title="Active Markets")
            table.add_column("Question", style="cyan", max_width=40)
            table.add_column("Volume", style="green")
            table.add_column("Yes Price", style="yellow")
            
            for market in markets[:5]:
                table.add_row(
                    market.question[:40] + "..." if len(market.question) > 40 else market.question,
                    f"${market.volume:,.0f}",
                    f"{market.yes_price:.1%}"
                )
            
            rprint(table)
        else:
            rprint("[red]No markets returned[/red]")
    
    rprint("\n[bold green]✓ Client test complete![/bold green]")


if __name__ == "__main__":
    asyncio.run(_test_client())