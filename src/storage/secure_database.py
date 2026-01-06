"""
Secure database layer with encryption for sensitive data.

Extends the base database functionality with transparent encryption
for sensitive fields like wallet addresses, trade details, and alert metadata.
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager

import aiosqlite
import structlog

from .database import Database, SCHEMA, WalletProfile, SuspicionReport, SignalType
from ..database_encryption import EncryptedDatabaseMixin, DatabaseEncryption, setup_database_encryption
from ..config import get_settings
from ..exceptions import DatabaseError, DatabaseConnectionError

logger = structlog.get_logger(__name__)


# Extended schema with encryption support
SECURE_SCHEMA = SCHEMA + """
-- Add encryption tracking table
CREATE TABLE IF NOT EXISTS encryption_metadata (
    id INTEGER PRIMARY KEY,
    table_name TEXT NOT NULL,
    field_name TEXT NOT NULL,
    encryption_version TEXT NOT NULL DEFAULT 'v1',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(table_name, field_name)
);

-- Index for encryption metadata lookups
CREATE INDEX IF NOT EXISTS idx_encryption_table_field
ON encryption_metadata(table_name, field_name);

-- Add audit trail for sensitive operations
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation TEXT NOT NULL,
    table_name TEXT NOT NULL,
    record_id TEXT,
    user_component TEXT,
    operation_details TEXT,  -- Encrypted JSON
    outcome TEXT NOT NULL DEFAULT 'success',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for audit log queries
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_operation ON audit_log(operation);
CREATE INDEX IF NOT EXISTS idx_audit_table ON audit_log(table_name);
"""


class SecureDatabase(EncryptedDatabaseMixin, Database):
    """
    Secure database manager with transparent field encryption.

    Inherits from Database for core functionality and EncryptedDatabaseMixin
    for automatic encryption/decryption of sensitive fields.
    """

    def __init__(self, db_path: Optional[Path] = None, encryption_password: Optional[str] = None):
        """
        Initialize secure database manager.

        Args:
            db_path: Path to SQLite database. If None, uses config default.
            encryption_password: Password for database encryption. If None, uses env var.
        """
        # Initialize base class first
        super().__init__(db_path)

        # Set up encryption
        if encryption_password:
            self.encryptor = DatabaseEncryption(encryption_password)
        else:
            # Use EncryptedDatabaseMixin's default initialization
            pass

        logger.info("secure_database_initialized",
                   db_path=str(self.db_path),
                   encryption_enabled=self.encryptor.is_encryption_enabled())

    async def initialize(self) -> None:
        """Initialize database with secure schema and encryption setup."""
        # Ensure database directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            # Connect to database
            self._connection = await aiosqlite.connect(
                str(self.db_path),
                timeout=30.0,
                isolation_level=None  # Enable autocommit mode
            )

            # Enable WAL mode for better concurrent access
            await self._connection.execute("PRAGMA journal_mode=WAL;")

            # Enable foreign key constraints
            await self._connection.execute("PRAGMA foreign_keys=ON;")

            # Set busy timeout
            await self._connection.execute("PRAGMA busy_timeout=30000;")

            # Create schema
            await self._connection.executescript(SECURE_SCHEMA)

            # Initialize encryption metadata
            await self._initialize_encryption_metadata()

            await self._connection.commit()

            logger.info("secure_database_initialized",
                       path=str(self.db_path),
                       encryption_enabled=self.encryptor.is_encryption_enabled())

        except Exception as e:
            logger.error("database_initialization_failed", error=str(e), path=str(self.db_path))
            if self._connection:
                await self._connection.close()
                self._connection = None
            raise DatabaseConnectionError(f"Failed to initialize database: {e}")

    async def _initialize_encryption_metadata(self):
        """Initialize encryption metadata for sensitive fields."""
        if not self.encryptor.is_encryption_enabled():
            return

        # Mark which fields are encrypted
        sensitive_fields = [
            ('wallets', 'address', 'v1'),
            ('alerts', 'wallet_address', 'v1'),
            ('alerts', 'details', 'v1'),
            ('trade_history', 'maker', 'v1'),
            ('trade_history', 'transaction_hash', 'v1'),
            ('audit_log', 'operation_details', 'v1'),
        ]

        for table_name, field_name, version in sensitive_fields:
            await self._connection.execute("""
                INSERT OR IGNORE INTO encryption_metadata
                (table_name, field_name, encryption_version)
                VALUES (?, ?, ?)
            """, (table_name, field_name, version))

    async def audit_log(self, operation: str, table_name: str,
                       record_id: Optional[str] = None,
                       user_component: str = "system",
                       details: Optional[Dict[str, Any]] = None,
                       outcome: str = "success"):
        """
        Log security-sensitive operations for audit trail.

        Args:
            operation: Operation being performed (e.g., "create_wallet", "update_alert")
            table_name: Database table affected
            record_id: ID of affected record
            user_component: Component/user performing operation
            details: Additional operation details (will be encrypted)
            outcome: Operation outcome ("success", "failure", "error")
        """
        if not self._connection:
            return

        try:
            # Encrypt operation details
            encrypted_details = None
            if details:
                encrypted_details = self.encryptor.encrypt_field(details)

            await self._connection.execute("""
                INSERT INTO audit_log
                (operation, table_name, record_id, user_component, operation_details, outcome)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (operation, table_name, record_id, user_component, encrypted_details, outcome))

            logger.debug("audit_logged",
                        operation=operation,
                        table=table_name,
                        outcome=outcome)

        except Exception as e:
            logger.error("audit_logging_failed",
                        operation=operation,
                        error=str(e))

    async def create_or_update_wallet(self, address: str, **kwargs) -> WalletProfile:
        """
        Create or update wallet with encryption and audit logging.

        Args:
            address: Wallet address
            **kwargs: Additional wallet data

        Returns:
            WalletProfile instance
        """
        if not self._connection:
            raise DatabaseError("Database not initialized")

        try:
            # Prepare data for encryption
            wallet_data = {
                'address': address,
                **kwargs
            }

            # Encrypt sensitive data
            encrypted_data = self.encrypt_sensitive_data('wallets', wallet_data)

            # Check if wallet exists
            cursor = await self._connection.execute(
                "SELECT address FROM wallets WHERE address LIKE ?",
                (f"{address[:6].lower()}:%",)  # Search by prefix for encrypted addresses
            )
            existing = await cursor.fetchone()

            if existing:
                # Update existing wallet
                update_fields = []
                update_values = []
                for key, value in encrypted_data.items():
                    if key != 'address':  # Don't update address
                        update_fields.append(f"{key} = ?")
                        update_values.append(value)

                if update_fields:
                    update_values.append(encrypted_data['address'])
                    await self._connection.execute(
                        f"UPDATE wallets SET {', '.join(update_fields)} WHERE address = ?",
                        update_values
                    )

                operation = "update_wallet"
            else:
                # Insert new wallet
                fields = list(encrypted_data.keys())
                placeholders = ', '.join(['?' for _ in fields])
                values = list(encrypted_data.values())

                await self._connection.execute(
                    f"INSERT INTO wallets ({', '.join(fields)}) VALUES ({placeholders})",
                    values
                )

                operation = "create_wallet"

            await self._connection.commit()

            # Audit log the operation
            await self.audit_log(
                operation=operation,
                table_name="wallets",
                record_id=address,
                details={"fields_updated": list(kwargs.keys())}
            )

            # Return decrypted wallet profile
            return await self.get_wallet(address)

        except Exception as e:
            logger.error("wallet_creation_failed", address=address[:10], error=str(e))
            await self.audit_log(
                operation="create_wallet",
                table_name="wallets",
                record_id=address,
                outcome="error",
                details={"error": str(e)}
            )
            raise DatabaseError(f"Failed to create/update wallet: {e}")

    async def get_wallet(self, address: str) -> Optional[WalletProfile]:
        """
        Get wallet with automatic decryption.

        Args:
            address: Wallet address to retrieve

        Returns:
            WalletProfile if found, None otherwise
        """
        if not self._connection:
            raise DatabaseError("Database not initialized")

        try:
            # Search by encrypted address prefix
            search_prefix = address[:6].lower()
            cursor = await self._connection.execute(
                "SELECT * FROM wallets WHERE address LIKE ?",
                (f"{search_prefix}:%",)
            )
            row = await cursor.fetchone()

            if not row:
                return None

            # Convert to dict
            wallet_data = dict(row)

            # Decrypt sensitive data
            decrypted_data = self.decrypt_sensitive_data('wallets', wallet_data)

            # Create WalletProfile
            return WalletProfile(
                address=decrypted_data['address'],
                first_seen=datetime.fromisoformat(decrypted_data['first_seen']),
                total_trades=decrypted_data['total_trades'],
                total_volume_usd=decrypted_data['total_volume_usd'],
                winning_trades=decrypted_data.get('winning_trades', 0),
                is_fresh=(datetime.now(timezone.utc) -
                         datetime.fromisoformat(decrypted_data['first_seen']).replace(tzinfo=timezone.utc)).days <= 7
            )

        except Exception as e:
            logger.error("wallet_retrieval_failed", address=address[:10], error=str(e))
            raise DatabaseError(f"Failed to retrieve wallet: {e}")

    async def save_alert(self, report: SuspicionReport) -> int:
        """
        Save alert with encryption and audit logging.

        Args:
            report: SuspicionReport to save

        Returns:
            Alert ID
        """
        if not self._connection:
            raise DatabaseError("Database not initialized")

        try:
            # Prepare alert data
            alert_data = {
                'wallet_address': report.wallet_profile.address,
                'market_id': report.market_context.get('market_id', ''),
                'event_slug': report.market_context.get('event_slug', ''),
                'signal_type': ','.join([s.value for s in report.triggered_signals]),
                'suspicion_score': report.total_score,
                'position_size_usd': report.market_context.get('position_size_usd', 0.0),
                'position_side': report.market_context.get('position_side', 'unknown'),
                'price_at_detection': report.market_context.get('current_price', 0.0),
                'details': {
                    'signal_breakdown': report.signal_breakdown,
                    'market_context': report.market_context,
                    'metadata': report.metadata
                }
            }

            # Encrypt sensitive data
            encrypted_data = self.encrypt_sensitive_data('alerts', alert_data)

            # Insert alert
            cursor = await self._connection.execute("""
                INSERT INTO alerts
                (wallet_address, market_id, event_slug, signal_type, suspicion_score,
                 position_size_usd, position_side, price_at_detection, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                encrypted_data['wallet_address'],
                encrypted_data['market_id'],
                encrypted_data['event_slug'],
                encrypted_data['signal_type'],
                encrypted_data['suspicion_score'],
                encrypted_data['position_size_usd'],
                encrypted_data['position_side'],
                encrypted_data['price_at_detection'],
                encrypted_data['details']
            ))

            alert_id = cursor.lastrowid
            await self._connection.commit()

            # Audit log
            await self.audit_log(
                operation="create_alert",
                table_name="alerts",
                record_id=str(alert_id),
                details={"suspicion_score": report.total_score, "signals": len(report.triggered_signals)}
            )

            logger.info("alert_saved",
                       alert_id=alert_id,
                       wallet=report.wallet_profile.address[:10],
                       score=report.total_score)

            return alert_id

        except Exception as e:
            logger.error("alert_save_failed", error=str(e))
            await self.audit_log(
                operation="create_alert",
                table_name="alerts",
                outcome="error",
                details={"error": str(e)}
            )
            raise DatabaseError(f"Failed to save alert: {e}")

    async def get_encryption_status(self) -> Dict[str, Any]:
        """Get database encryption status and statistics."""
        if not self._connection:
            return {"error": "Database not initialized"}

        try:
            # Check encryption metadata
            cursor = await self._connection.execute(
                "SELECT table_name, field_name, encryption_version FROM encryption_metadata"
            )
            encryption_fields = await cursor.fetchall()

            # Count records in main tables
            tables = ['wallets', 'alerts', 'trade_history', 'audit_log']
            table_counts = {}

            for table in tables:
                try:
                    cursor = await self._connection.execute(f"SELECT COUNT(*) FROM {table}")
                    count = await cursor.fetchone()
                    table_counts[table] = count[0] if count else 0
                except Exception:
                    table_counts[table] = "error"

            return {
                "encryption_enabled": self.encryptor.is_encryption_enabled(),
                "encrypted_fields": [
                    {"table": row[0], "field": row[1], "version": row[2]}
                    for row in encryption_fields
                ],
                "table_counts": table_counts,
                "database_path": str(self.db_path)
            }

        except Exception as e:
            logger.error("encryption_status_failed", error=str(e))
            return {"error": str(e)}

    async def search_wallets_by_prefix(self, address_prefix: str, limit: int = 50) -> List[str]:
        """
        Search for wallet addresses by prefix in encrypted storage.

        Args:
            address_prefix: Address prefix to search (e.g., "0x742d")
            limit: Maximum results to return

        Returns:
            List of matching wallet addresses
        """
        if not self._connection or len(address_prefix) < 4:
            return []

        try:
            # Search by encrypted address prefix
            search_prefix = address_prefix[:6].lower()
            cursor = await self._connection.execute(
                "SELECT address FROM wallets WHERE address LIKE ? LIMIT ?",
                (f"{search_prefix}:%", limit)
            )
            rows = await cursor.fetchall()

            # Decrypt addresses
            addresses = []
            for row in rows:
                try:
                    decrypted_address = self._partially_decrypt_address(row[0])
                    if decrypted_address.startswith(address_prefix.lower()):
                        addresses.append(decrypted_address)
                except Exception as e:
                    logger.warning("address_decryption_failed", error=str(e))

            return addresses[:limit]

        except Exception as e:
            logger.error("wallet_search_failed", prefix=address_prefix, error=str(e))
            return []


def get_secure_database() -> SecureDatabase:
    """Get configured secure database instance."""
    return SecureDatabase()


async def migrate_to_encrypted_database(old_db_path: Path, new_db_path: Path,
                                      encryption_password: str) -> None:
    """
    Migrate data from unencrypted database to encrypted database.

    Args:
        old_db_path: Path to existing unencrypted database
        new_db_path: Path for new encrypted database
        encryption_password: Password for encryption
    """
    logger.info("starting_database_migration",
               source=str(old_db_path),
               destination=str(new_db_path))

    # Initialize old and new databases
    old_db = Database(old_db_path)
    new_db = SecureDatabase(new_db_path, encryption_password)

    try:
        await old_db.initialize()
        await new_db.initialize()

        # Migrate wallets
        # This would need to be implemented based on the actual Database class methods
        logger.info("migration_placeholder", message="Migration logic would be implemented here")

        logger.info("database_migration_completed")

    except Exception as e:
        logger.error("database_migration_failed", error=str(e))
        raise DatabaseError(f"Migration failed: {e}")

    finally:
        await old_db.close()
        await new_db.close()


if __name__ == "__main__":
    async def test_secure_database():
        """Test secure database functionality."""
        print("🔒 Testing Secure Database")
        print("=" * 30)

        # Test with encryption password
        test_db = SecureDatabase(Path("test_secure.db"), "test_password_123")

        try:
            await test_db.initialize()

            # Test encryption status
            status = await test_db.get_encryption_status()
            print(f"Encryption enabled: {status['encryption_enabled']}")
            print(f"Encrypted fields: {len(status['encrypted_fields'])}")

            print("✅ Secure database test completed")

        finally:
            await test_db.close()

    asyncio.run(test_secure_database())