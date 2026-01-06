"""
Pydantic schemas for validating external API data.

All data from Polymarket APIs should be validated through these schemas
before being used in the application. This prevents malformed or malicious
data from causing runtime errors.
"""

from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, validator
from .validation import (
    WalletAddressValidator,
    MarketValidator,
    NumericValidator,
    ValidationError
)


class PolymarketMarketSchema(BaseModel):
    """Schema for Polymarket market data from Gamma API."""

    id: str = Field(..., description="Market token ID")
    question: str = Field(..., description="Market question")
    description: Optional[str] = Field(None, description="Market description")
    end_date_iso: Optional[str] = Field(None, description="Market end date")
    game_start_time: Optional[str] = Field(None, description="Game start time")
    seconds_delay: Optional[int] = Field(None, description="Resolution delay")
    fpmm: Optional[str] = Field(None, description="Market maker address")
    maker_base_fee: Optional[str] = Field(None, description="Base maker fee")
    maker_fee: Optional[str] = Field(None, description="Current maker fee")
    liquidity: Optional[str] = Field(None, description="Total liquidity")
    volume: Optional[str] = Field(None, description="Total volume")
    volume_24hr: Optional[str] = Field(None, description="24h volume")
    outcome_prices: Optional[List[str]] = Field(None, description="Current prices")
    clob_token_ids: Optional[List[str]] = Field(None, description="CLOB token IDs")
    condition_id: Optional[str] = Field(None, description="Condition ID")
    question_id: Optional[str] = Field(None, description="Question ID")
    tokens: Optional[List[Dict[str, Any]]] = Field(None, description="Token info")
    minimum_order_size: Optional[str] = Field(None, description="Min order size")
    minimum_tick_size: Optional[str] = Field(None, description="Min tick size")
    active: Optional[bool] = Field(True, description="Market active status")
    closed: Optional[bool] = Field(False, description="Market closed status")
    archived: Optional[bool] = Field(False, description="Market archived status")
    accepting_orders: Optional[bool] = Field(True, description="Accepting orders")
    accepting_order_timestamp: Optional[str] = Field(None, description="Accept orders since")
    neg_risk: Optional[bool] = Field(False, description="Negative risk flag")
    rewards: Optional[Dict[str, Any]] = Field(None, description="Reward info")

    @validator('id')
    def validate_market_id(cls, v):
        return MarketValidator.validate_token_id(v)

    @validator('fpmm', pre=True)
    def validate_fpmm_address(cls, v):
        if v and isinstance(v, str):
            return WalletAddressValidator.validate(v)
        return v

    @validator('liquidity', 'volume', 'volume_24hr', 'maker_base_fee', 'maker_fee',
               'minimum_order_size', 'minimum_tick_size', pre=True)
    def validate_numeric_fields(cls, v):
        if v is not None and v != "":
            return str(NumericValidator.validate_volume(v))
        return v

    @validator('outcome_prices', 'clob_token_ids', pre=True)
    def validate_lists(cls, v):
        if v is None:
            return None
        if not isinstance(v, list):
            raise ValidationError(f"Expected list, got {type(v)}")
        return v

    class Config:
        extra = 'ignore'  # Ignore extra fields from API


class PolymarketEventSchema(BaseModel):
    """Schema for Polymarket event data from Gamma API."""

    id: str = Field(..., description="Event ID")
    title: str = Field(..., description="Event title")
    description: Optional[str] = Field(None, description="Event description")
    slug: str = Field(..., description="Event slug")
    start_date_iso: Optional[str] = Field(None, description="Event start date")
    end_date_iso: Optional[str] = Field(None, description="Event end date")
    image_url: Optional[str] = Field(None, description="Event image URL")
    icon_url: Optional[str] = Field(None, description="Event icon URL")
    active: Optional[bool] = Field(True, description="Event active status")
    closed: Optional[bool] = Field(False, description="Event closed status")
    archived: Optional[bool] = Field(False, description="Event archived status")
    restricted: Optional[bool] = Field(False, description="Event restricted status")
    liquidity: Optional[str] = Field(None, description="Total event liquidity")
    volume: Optional[str] = Field(None, description="Total event volume")
    volume_24hr: Optional[str] = Field(None, description="24h event volume")
    comment_count: Optional[int] = Field(None, description="Comment count")
    markets: Optional[List[str]] = Field(None, description="Market IDs in event")
    tags: Optional[List[str]] = Field(None, description="Event tags")

    @validator('slug')
    def validate_slug(cls, v):
        return MarketValidator.validate_market_slug(v)

    @validator('liquidity', 'volume', 'volume_24hr', pre=True)
    def validate_numeric_fields(cls, v):
        if v is not None and v != "":
            return str(NumericValidator.validate_volume(v))
        return v

    @validator('markets', 'tags', pre=True)
    def validate_lists(cls, v):
        if v is None:
            return None
        if not isinstance(v, list):
            raise ValidationError(f"Expected list, got {type(v)}")
        return v

    class Config:
        extra = 'ignore'


class PolymarketTradeSchema(BaseModel):
    """Schema for Polymarket trade data from CLOB API."""

    id: Optional[str] = Field(None, description="Trade ID")
    taker_order_id: Optional[str] = Field(None, description="Taker order ID")
    maker_order_id: Optional[str] = Field(None, description="Maker order ID")
    market: str = Field(..., description="Market token ID")
    asset_id: Optional[str] = Field(None, description="Asset ID")
    side: str = Field(..., description="Trade side")
    size: str = Field(..., description="Trade size")
    price: str = Field(..., description="Trade price")
    fee_rate_bps: Optional[str] = Field(None, description="Fee rate in bps")
    fee: Optional[str] = Field(None, description="Fee amount")
    taker: str = Field(..., description="Taker address")
    maker: str = Field(..., description="Maker address")
    timestamp: Optional[str] = Field(None, description="Trade timestamp")
    transaction_hash: Optional[str] = Field(None, description="Transaction hash")
    outcome: Optional[str] = Field(None, description="Outcome token")
    bucket_index: Optional[int] = Field(None, description="Bucket index")
    match_time: Optional[str] = Field(None, description="Match timestamp")

    @validator('market', 'asset_id', pre=True)
    def validate_market_fields(cls, v):
        if v:
            return MarketValidator.validate_token_id(v)
        return v

    @validator('taker', 'maker')
    def validate_addresses(cls, v):
        return WalletAddressValidator.validate(v)

    @validator('size', 'price')
    def validate_trade_amounts(cls, v):
        return str(NumericValidator.validate_volume(v))

    @validator('fee', 'fee_rate_bps', pre=True)
    def validate_fee_fields(cls, v):
        if v is not None and v != "":
            return str(NumericValidator.validate_volume(v))
        return v

    @validator('side')
    def validate_side(cls, v):
        valid_sides = {'BUY', 'SELL', 'YES', 'NO'}
        if v.upper() not in valid_sides:
            raise ValidationError(f"Invalid trade side: {v}")
        return v.upper()

    class Config:
        extra = 'ignore'


class PolymarketPositionSchema(BaseModel):
    """Schema for wallet position data from CLOB API."""

    asset_id: str = Field(..., description="Asset/token ID")
    market: Optional[str] = Field(None, description="Market ID")
    side: str = Field(..., description="Position side")
    size: str = Field(..., description="Position size")
    value: Optional[str] = Field(None, description="Position value")
    average_price: Optional[str] = Field(None, description="Average entry price")
    latest_trade_price: Optional[str] = Field(None, description="Latest trade price")
    realized_pnl: Optional[str] = Field(None, description="Realized PnL")
    unrealized_pnl: Optional[str] = Field(None, description="Unrealized PnL")

    @validator('asset_id', 'market', pre=True)
    def validate_market_fields(cls, v):
        if v:
            return MarketValidator.validate_token_id(v)
        return v

    @validator('side')
    def validate_side(cls, v):
        valid_sides = {'LONG', 'SHORT', 'YES', 'NO'}
        if v.upper() not in valid_sides:
            raise ValidationError(f"Invalid position side: {v}")
        return v.upper()

    @validator('size', 'value', 'average_price', 'latest_trade_price',
               'realized_pnl', 'unrealized_pnl', pre=True)
    def validate_numeric_fields(cls, v):
        if v is not None and v != "":
            return str(NumericValidator.validate_volume(v))
        return v

    class Config:
        extra = 'ignore'


class PolymarketOrderBookSchema(BaseModel):
    """Schema for order book data from CLOB API."""

    market: str = Field(..., description="Market token ID")
    asset_id: str = Field(..., description="Asset ID")
    hash: Optional[str] = Field(None, description="Order book hash")
    bids: List[Dict[str, str]] = Field(..., description="Bid orders")
    asks: List[Dict[str, str]] = Field(..., description="Ask orders")

    @validator('market', 'asset_id')
    def validate_market_fields(cls, v):
        return MarketValidator.validate_token_id(v)

    @validator('bids', 'asks')
    def validate_orders(cls, v):
        if not isinstance(v, list):
            raise ValidationError(f"Expected list, got {type(v)}")

        for order in v:
            if not isinstance(order, dict):
                continue

            # Validate price and size if present
            if 'price' in order:
                NumericValidator.validate_price(order['price'])
            if 'size' in order:
                NumericValidator.validate_volume(order['size'])

        return v

    class Config:
        extra = 'ignore'


class WalletAnalysisSchema(BaseModel):
    """Schema for internal wallet analysis data."""

    address: str = Field(..., description="Wallet address")
    first_seen: Optional[datetime] = Field(None, description="First seen timestamp")
    total_trades: int = Field(default=0, description="Total trade count")
    total_volume_usd: Decimal = Field(default=Decimal('0'), description="Total volume")
    win_rate: Optional[float] = Field(None, description="Win rate percentage")
    last_updated: Optional[datetime] = Field(None, description="Last update time")
    is_fresh: bool = Field(default=False, description="Is fresh wallet flag")
    risk_score: Optional[int] = Field(None, description="Risk score 0-100")

    @validator('address')
    def validate_address(cls, v):
        return WalletAddressValidator.validate(v)

    @validator('win_rate', pre=True)
    def validate_win_rate(cls, v):
        if v is not None:
            if not 0 <= float(v) <= 100:
                raise ValidationError(f"Win rate must be 0-100, got {v}")
        return v

    @validator('risk_score', pre=True)
    def validate_risk_score(cls, v):
        if v is not None:
            if not 0 <= int(v) <= 100:
                raise ValidationError(f"Risk score must be 0-100, got {v}")
        return v

    class Config:
        extra = 'forbid'  # Strict validation for internal data


class SuspiciousActivitySchema(BaseModel):
    """Schema for suspicious activity alerts."""

    wallet_address: str = Field(..., description="Suspicious wallet")
    market_id: str = Field(..., description="Market involved")
    signal_type: str = Field(..., description="Detection signal triggered")
    suspicion_score: int = Field(..., description="Suspicion score 0-100")
    position_size_usd: Decimal = Field(..., description="Position size in USD")
    position_side: str = Field(..., description="Position side")
    price_at_detection: Decimal = Field(..., description="Price when detected")
    detection_timestamp: datetime = Field(..., description="Detection time")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")

    @validator('wallet_address')
    def validate_address(cls, v):
        return WalletAddressValidator.validate(v)

    @validator('market_id')
    def validate_market(cls, v):
        return MarketValidator.validate_token_id(v)

    @validator('suspicion_score')
    def validate_score(cls, v):
        if not 0 <= v <= 100:
            raise ValidationError(f"Suspicion score must be 0-100, got {v}")
        return v

    @validator('position_side')
    def validate_side(cls, v):
        valid_sides = {'YES', 'NO', 'LONG', 'SHORT'}
        if v.upper() not in valid_sides:
            raise ValidationError(f"Invalid position side: {v}")
        return v.upper()

    @validator('signal_type')
    def validate_signal_type(cls, v):
        valid_signals = {
            'fresh_wallet', 'unusual_sizing', 'niche_concentration',
            'timing_pattern', 'repeat_winner', 'coordinated_activity'
        }
        if v not in valid_signals:
            raise ValidationError(f"Invalid signal type: {v}")
        return v

    class Config:
        extra = 'forbid'