"""
Database encryption layer for sensitive data protection.

Provides transparent encryption/decryption for sensitive fields in the database,
ensuring that private data like wallet addresses, trade details, and alert
information is encrypted at rest.
"""

import base64
import json
import os
from typing import Any, Dict, List, Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import structlog

from .exceptions import DatabaseError, ConfigurationError

logger = structlog.get_logger(__name__)


class DatabaseEncryption:
    """
    Handles encryption/decryption of sensitive database fields.

    Uses Fernet (AES 128 in CBC mode) for symmetric encryption with
    PBKDF2 key derivation from a master password.
    """

    def __init__(self, master_password: Optional[str] = None, salt: Optional[bytes] = None):
        self.master_password = master_password or os.getenv("DB_ENCRYPTION_PASSWORD", "")
        self.salt = salt or b'crystal_ball_db_salt_v1'  # In production, use random salt per DB
        self._cipher_suite: Optional[Fernet] = None

        if not self.master_password:
            logger.warning("database_encryption_disabled",
                          reason="No DB_ENCRYPTION_PASSWORD provided")
        else:
            logger.info("database_encryption_enabled")

    def _get_cipher_suite(self) -> Fernet:
        """Get or create Fernet cipher suite for encryption."""
        if self._cipher_suite is None:
            if not self.master_password:
                raise ConfigurationError(
                    "db_encryption_password",
                    "Database encryption password required but not provided"
                )

            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
            )

            key = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
            self._cipher_suite = Fernet(key)

            logger.debug("database_cipher_initialized")

        return self._cipher_suite

    def encrypt_field(self, value: Any) -> str:
        """
        Encrypt a field value for database storage.

        Args:
            value: Value to encrypt (will be JSON serialized)

        Returns:
            Base64-encoded encrypted string
        """
        if not self.master_password:
            # Return as-is if encryption is disabled
            return json.dumps(value) if not isinstance(value, str) else value

        try:
            # Serialize value to JSON
            json_value = json.dumps(value) if not isinstance(value, str) else value

            # Encrypt
            cipher = self._get_cipher_suite()
            encrypted_bytes = cipher.encrypt(json_value.encode('utf-8'))

            # Return base64 encoded
            return base64.urlsafe_b64encode(encrypted_bytes).decode('ascii')

        except Exception as e:
            logger.error("field_encryption_failed", error=str(e), value_type=type(value).__name__)
            raise DatabaseError(f"Failed to encrypt field: {e}")

    def decrypt_field(self, encrypted_value: str, default: Any = None) -> Any:
        """
        Decrypt a field value from database storage.

        Args:
            encrypted_value: Base64-encoded encrypted string
            default: Default value if decryption fails

        Returns:
            Decrypted and deserialized value
        """
        if not encrypted_value:
            return default

        if not self.master_password:
            # Try to parse as JSON if encryption is disabled
            try:
                return json.loads(encrypted_value)
            except json.JSONDecodeError:
                return encrypted_value

        try:
            # Decode from base64
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_value.encode('ascii'))

            # Decrypt
            cipher = self._get_cipher_suite()
            decrypted_bytes = cipher.decrypt(encrypted_bytes)

            # Deserialize JSON
            json_value = decrypted_bytes.decode('utf-8')

            try:
                return json.loads(json_value)
            except json.JSONDecodeError:
                # Return as string if not valid JSON
                return json_value

        except Exception as e:
            logger.warning("field_decryption_failed",
                          error=str(e),
                          encrypted_value_length=len(encrypted_value))
            return default

    def is_encryption_enabled(self) -> bool:
        """Check if database encryption is enabled."""
        return bool(self.master_password)


# Field-specific encryption helpers
class EncryptedField:
    """Descriptor for automatically encrypted database fields."""

    def __init__(self, field_name: str, encryptor: DatabaseEncryption):
        self.field_name = field_name
        self.encrypted_field_name = f"{field_name}_encrypted"
        self.encryptor = encryptor

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self

        # Get encrypted value from object
        encrypted_value = getattr(obj, self.encrypted_field_name, None)
        if encrypted_value is None:
            return None

        # Decrypt and return
        return self.encryptor.decrypt_field(encrypted_value)

    def __set__(self, obj, value):
        if value is None:
            setattr(obj, self.encrypted_field_name, None)
        else:
            # Encrypt and store
            encrypted_value = self.encryptor.encrypt_field(value)
            setattr(obj, self.encrypted_field_name, encrypted_value)


# Sensitive field definitions for each table
SENSITIVE_FIELDS = {
    'wallets': {
        'address': 'wallet_address',  # Partially sensitive (show first/last chars)
        'metadata': 'wallet_metadata',  # Fully encrypted JSON
    },
    'alerts': {
        'wallet_address': 'wallet_address',
        'details': 'alert_details',  # Fully encrypted JSON
        'metadata': 'alert_metadata',  # Fully encrypted JSON
    },
    'trade_history': {
        'wallet_address': 'wallet_address',
        'transaction_hash': 'transaction_hash',
        'details': 'trade_details',  # Fully encrypted JSON
    }
}


class EncryptedDatabaseMixin:
    """
    Mixin class for database operations with field encryption.

    Automatically encrypts sensitive fields before storage and
    decrypts them after retrieval.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.encryptor = DatabaseEncryption()

        logger.info("database_encryption_mixin_initialized",
                   encryption_enabled=self.encryptor.is_encryption_enabled())

    def encrypt_sensitive_data(self, table: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt sensitive fields in data before database insertion.

        Args:
            table: Database table name
            data: Data dictionary to encrypt

        Returns:
            Data with sensitive fields encrypted
        """
        if not self.encryptor.is_encryption_enabled():
            return data

        if table not in SENSITIVE_FIELDS:
            return data

        encrypted_data = data.copy()
        sensitive_fields = SENSITIVE_FIELDS[table]

        for field_name, field_type in sensitive_fields.items():
            if field_name in encrypted_data:
                original_value = encrypted_data[field_name]

                try:
                    if field_type == 'wallet_address':
                        # Partially encrypt wallet addresses (keep them searchable)
                        encrypted_data[field_name] = self._partially_encrypt_address(original_value)
                    else:
                        # Fully encrypt other sensitive fields
                        encrypted_data[field_name] = self.encryptor.encrypt_field(original_value)

                    logger.debug("field_encrypted",
                               table=table,
                               field=field_name,
                               field_type=field_type)

                except Exception as e:
                    logger.error("field_encryption_error",
                               table=table,
                               field=field_name,
                               error=str(e))
                    # Continue with unencrypted value

        return encrypted_data

    def decrypt_sensitive_data(self, table: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt sensitive fields in data after database retrieval.

        Args:
            table: Database table name
            data: Data dictionary to decrypt

        Returns:
            Data with sensitive fields decrypted
        """
        if not self.encryptor.is_encryption_enabled():
            return data

        if table not in SENSITIVE_FIELDS:
            return data

        decrypted_data = data.copy()
        sensitive_fields = SENSITIVE_FIELDS[table]

        for field_name, field_type in sensitive_fields.items():
            if field_name in decrypted_data and decrypted_data[field_name]:
                encrypted_value = decrypted_data[field_name]

                try:
                    if field_type == 'wallet_address':
                        # Partially decrypt wallet addresses
                        decrypted_data[field_name] = self._partially_decrypt_address(encrypted_value)
                    else:
                        # Fully decrypt other sensitive fields
                        decrypted_data[field_name] = self.encryptor.decrypt_field(
                            encrypted_value,
                            default=encrypted_value
                        )

                    logger.debug("field_decrypted",
                               table=table,
                               field=field_name,
                               field_type=field_type)

                except Exception as e:
                    logger.warning("field_decryption_error",
                                 table=table,
                                 field=field_name,
                                 error=str(e))
                    # Continue with encrypted value

        return decrypted_data

    def _partially_encrypt_address(self, address: str) -> str:
        """
        Partially encrypt wallet addresses to maintain searchability.

        Stores first 6 chars + encrypted full address for search capabilities.
        """
        if not address or len(address) < 10:
            return address

        # Keep first 6 characters for prefix searching
        prefix = address[:6].lower()

        # Encrypt full address
        encrypted_full = self.encryptor.encrypt_field(address.lower())

        # Store as: "prefix:encrypted_full"
        return f"{prefix}:{encrypted_full}"

    def _partially_decrypt_address(self, partial_encrypted: str) -> str:
        """Decrypt partially encrypted wallet address."""
        if ':' not in partial_encrypted:
            # Not encrypted or old format
            return partial_encrypted

        try:
            prefix, encrypted_part = partial_encrypted.split(':', 1)
            full_address = self.encryptor.decrypt_field(encrypted_part)
            return full_address if full_address else partial_encrypted
        except Exception:
            return partial_encrypted

    def search_encrypted_addresses(self, address_prefix: str, limit: int = 100) -> List[str]:
        """
        Search for addresses by prefix in encrypted storage.

        Args:
            address_prefix: Address prefix to search for (e.g., "0x742d")
            limit: Maximum number of results

        Returns:
            List of matching full addresses
        """
        if not address_prefix or len(address_prefix) < 4:
            return []

        # Search by prefix in database
        prefix_pattern = address_prefix[:6].lower()

        # This would be implemented in the actual database class
        # For now, return empty list
        logger.debug("encrypted_address_search",
                    prefix=prefix_pattern,
                    limit=limit)
        return []


def setup_database_encryption(password: str) -> DatabaseEncryption:
    """
    Set up database encryption with the provided password.

    Args:
        password: Master password for database encryption

    Returns:
        Configured DatabaseEncryption instance
    """
    if len(password) < 12:
        raise ConfigurationError(
            "db_encryption_password",
            "Database encryption password must be at least 12 characters"
        )

    # Set environment variable for other components
    os.environ["DB_ENCRYPTION_PASSWORD"] = password

    # Create encryptor
    encryptor = DatabaseEncryption(password)

    logger.info("database_encryption_setup_complete",
               encryption_enabled=encryptor.is_encryption_enabled())

    return encryptor


def test_database_encryption():
    """Test database encryption functionality."""
    print("🔒 Testing Database Encryption")
    print("=" * 40)

    # Test with sample data
    test_password = "test_encryption_password_123"
    encryptor = DatabaseEncryption(test_password)

    # Test data
    test_cases = [
        ("Wallet Address", "0x742dE5a9b5fc17a187B86EC36B7b49B1B9F90a4f"),
        ("Trade Details", {
            "market_id": "12345",
            "size": "100.5",
            "price": "0.75",
            "timestamp": "2024-01-01T00:00:00Z"
        }),
        ("Alert Metadata", {
            "signal_type": "fresh_wallet",
            "confidence": 0.85,
            "triggers": ["low_history", "large_position"]
        }),
    ]

    for name, test_data in test_cases:
        print(f"\n{name}:")
        print(f"  Original: {test_data}")

        # Encrypt
        encrypted = encryptor.encrypt_field(test_data)
        print(f"  Encrypted: {encrypted[:50]}..." if len(encrypted) > 50 else f"  Encrypted: {encrypted}")

        # Decrypt
        decrypted = encryptor.decrypt_field(encrypted)
        print(f"  Decrypted: {decrypted}")

        # Verify
        success = test_data == decrypted
        print(f"  ✅ Match: {success}")

    print(f"\n✅ Database encryption test completed!")


if __name__ == "__main__":
    test_database_encryption()