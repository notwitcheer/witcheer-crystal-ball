"""
Input validation layer for Witcher's Crystal Ball.

Provides robust validation for all external data inputs including:
- Wallet addresses (Ethereum format)
- Market IDs and token IDs
- API response data sanitization
- User input sanitization
"""

import re
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, validator
from decimal import Decimal


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class WalletAddressValidator:
    """Validates Ethereum wallet addresses."""

    # Ethereum address pattern: 0x followed by 40 hexadecimal characters
    ETH_ADDRESS_PATTERN = re.compile(r'^0x[a-fA-F0-9]{40}$')

    @classmethod
    def validate(cls, address: str) -> str:
        """
        Validate and normalize an Ethereum wallet address.

        Args:
            address: Raw wallet address string

        Returns:
            Normalized wallet address (lowercase)

        Raises:
            ValidationError: If address format is invalid
        """
        if not isinstance(address, str):
            raise ValidationError(f"Wallet address must be string, got {type(address)}")

        # Remove whitespace
        address = address.strip()

        if not address:
            raise ValidationError("Wallet address cannot be empty")

        if not cls.ETH_ADDRESS_PATTERN.match(address):
            raise ValidationError(f"Invalid Ethereum address format: {address}")

        # Return normalized (lowercase) address
        return address.lower()

    @classmethod
    def is_valid(cls, address: str) -> bool:
        """Check if address is valid without raising exception."""
        try:
            cls.validate(address)
            return True
        except ValidationError:
            return False


class MarketValidator:
    """Validates market and token IDs."""

    # Token IDs are typically long integers or hex strings
    TOKEN_ID_PATTERN = re.compile(r'^(0x[a-fA-F0-9]+|\d+)$')

    @classmethod
    def validate_token_id(cls, token_id: Union[str, int]) -> str:
        """
        Validate and normalize a token/market ID.

        Args:
            token_id: Raw token ID

        Returns:
            Normalized token ID as string

        Raises:
            ValidationError: If token ID format is invalid
        """
        if isinstance(token_id, int):
            if token_id < 0:
                raise ValidationError(f"Token ID must be positive, got {token_id}")
            return str(token_id)

        if not isinstance(token_id, str):
            raise ValidationError(f"Token ID must be string or int, got {type(token_id)}")

        token_id = token_id.strip()

        if not token_id:
            raise ValidationError("Token ID cannot be empty")

        if not cls.TOKEN_ID_PATTERN.match(token_id):
            raise ValidationError(f"Invalid token ID format: {token_id}")

        return token_id

    @classmethod
    def validate_market_slug(cls, slug: str) -> str:
        """
        Validate and normalize a market event slug.

        Args:
            slug: Raw event slug

        Returns:
            Normalized slug

        Raises:
            ValidationError: If slug format is invalid
        """
        if not isinstance(slug, str):
            raise ValidationError(f"Market slug must be string, got {type(slug)}")

        slug = slug.strip()

        if not slug:
            raise ValidationError("Market slug cannot be empty")

        # Basic slug validation: alphanumeric, hyphens, underscores
        if not re.match(r'^[a-zA-Z0-9_-]+$', slug):
            raise ValidationError(f"Invalid market slug format: {slug}")

        return slug.lower()


class NumericValidator:
    """Validates numeric inputs for financial data."""

    @classmethod
    def validate_price(cls, price: Union[str, float, int, Decimal]) -> Decimal:
        """
        Validate and normalize a price value.

        Args:
            price: Raw price value

        Returns:
            Normalized price as Decimal

        Raises:
            ValidationError: If price is invalid
        """
        try:
            price_decimal = Decimal(str(price))
        except (ValueError, TypeError) as e:
            raise ValidationError(f"Invalid price format: {price} - {e}")

        if price_decimal < 0:
            raise ValidationError(f"Price cannot be negative: {price_decimal}")

        if price_decimal > 1:
            raise ValidationError(f"Polymarket prices must be ≤ 1.0: {price_decimal}")

        return price_decimal

    @classmethod
    def validate_volume(cls, volume: Union[str, float, int, Decimal]) -> Decimal:
        """
        Validate and normalize a volume value.

        Args:
            volume: Raw volume value

        Returns:
            Normalized volume as Decimal

        Raises:
            ValidationError: If volume is invalid
        """
        try:
            volume_decimal = Decimal(str(volume))
        except (ValueError, TypeError) as e:
            raise ValidationError(f"Invalid volume format: {volume} - {e}")

        if volume_decimal < 0:
            raise ValidationError(f"Volume cannot be negative: {volume_decimal}")

        return volume_decimal


class ApiResponseValidator(BaseModel):
    """Validates and sanitizes API response data."""

    class Config:
        """Pydantic config for strict validation."""
        extra = 'forbid'  # Reject unknown fields
        validate_assignment = True

    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a dictionary from API response.

        Removes potentially dangerous keys and validates common fields.

        Args:
            data: Raw dictionary from API

        Returns:
            Sanitized dictionary
        """
        if not isinstance(data, dict):
            raise ValidationError(f"Expected dict, got {type(data)}")

        # List of keys to remove for security
        dangerous_keys = {
            '__proto__', 'constructor', 'prototype',
            'eval', 'function', 'script', 'iframe'
        }

        sanitized = {}
        for key, value in data.items():
            # Skip dangerous keys
            if key.lower() in dangerous_keys:
                continue

            # Sanitize string values
            if isinstance(value, str):
                value = cls._sanitize_string(value)
            elif isinstance(value, dict):
                value = cls.sanitize_dict(value)
            elif isinstance(value, list):
                value = cls._sanitize_list(value)

            sanitized[key] = value

        return sanitized

    @classmethod
    def _sanitize_string(cls, text: str) -> str:
        """Sanitize a string value."""
        if not isinstance(text, str):
            return text

        # Remove potential script injections
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'data:text/html',
            r'vbscript:',
        ]

        for pattern in dangerous_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE | re.DOTALL)

        return text.strip()

    @classmethod
    def _sanitize_list(cls, items: List[Any]) -> List[Any]:
        """Sanitize a list of items."""
        sanitized = []
        for item in items:
            if isinstance(item, str):
                item = cls._sanitize_string(item)
            elif isinstance(item, dict):
                item = cls.sanitize_dict(item)
            elif isinstance(item, list):
                item = cls._sanitize_list(item)

            sanitized.append(item)

        return sanitized


class TradeDataValidator(BaseModel):
    """Validates trade data from API responses."""

    market: str = Field(..., description="Market/token ID")
    maker: str = Field(..., description="Maker wallet address")
    taker: str = Field(..., description="Taker wallet address")
    price: Decimal = Field(..., description="Trade price")
    size: Decimal = Field(..., description="Trade size")
    side: str = Field(..., description="Trade side (BUY/SELL)")

    @validator('market')
    def validate_market(cls, v):
        return MarketValidator.validate_token_id(v)

    @validator('maker', 'taker')
    def validate_addresses(cls, v):
        return WalletAddressValidator.validate(v)

    @validator('price')
    def validate_price(cls, v):
        return NumericValidator.validate_price(v)

    @validator('size')
    def validate_size(cls, v):
        return NumericValidator.validate_volume(v)

    @validator('side')
    def validate_side(cls, v):
        if v.upper() not in ('BUY', 'SELL', 'YES', 'NO'):
            raise ValueError(f"Invalid trade side: {v}")
        return v.upper()


def validate_wallet_address(address: str) -> str:
    """Convenience function for wallet address validation."""
    return WalletAddressValidator.validate(address)


def validate_market_id(market_id: Union[str, int]) -> str:
    """Convenience function for market ID validation."""
    return MarketValidator.validate_token_id(market_id)


def sanitize_api_response(data: Union[Dict, List]) -> Union[Dict, List]:
    """Convenience function for API response sanitization."""
    if isinstance(data, dict):
        return ApiResponseValidator.sanitize_dict(data)
    elif isinstance(data, list):
        return ApiResponseValidator._sanitize_list(data)
    else:
        raise ValidationError(f"Expected dict or list, got {type(data)}")