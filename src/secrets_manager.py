"""
Secure secrets management for Witcher's Crystal Ball.

Provides secure storage and retrieval of sensitive data like private keys,
API tokens, and other credentials. Supports multiple backends with fallback
to environment variables for development.
"""

import os
import json
import base64
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import structlog

from .exceptions import ConfigurationError, MissingConfigError

logger = structlog.get_logger(__name__)


class SecretsBackend(ABC):
    """Abstract base class for secrets storage backends."""

    @abstractmethod
    async def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret by key."""
        pass

    @abstractmethod
    async def set_secret(self, key: str, value: str) -> None:
        """Store a secret."""
        pass

    @abstractmethod
    async def delete_secret(self, key: str) -> None:
        """Delete a secret."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if backend is available."""
        pass


class EnvironmentSecretsBackend(SecretsBackend):
    """Fallback backend that reads from environment variables."""

    def __init__(self, prefix: str = ""):
        self.prefix = prefix

    async def get_secret(self, key: str) -> Optional[str]:
        """Get secret from environment variable."""
        env_key = f"{self.prefix}{key}" if self.prefix else key
        value = os.getenv(env_key)

        if value:
            logger.debug("secret_retrieved_from_env", key=key, env_key=env_key)

        return value

    async def set_secret(self, key: str, value: str) -> None:
        """Set environment variable (for development only)."""
        env_key = f"{self.prefix}{key}" if self.prefix else key
        os.environ[env_key] = value
        logger.warning("secret_set_in_env", key=key, env_key=env_key)

    async def delete_secret(self, key: str) -> None:
        """Delete environment variable."""
        env_key = f"{self.prefix}{key}" if self.prefix else key
        if env_key in os.environ:
            del os.environ[env_key]
            logger.info("secret_deleted_from_env", key=key, env_key=env_key)

    def is_available(self) -> bool:
        """Environment variables are always available."""
        return True


class EncryptedFileSecretsBackend(SecretsBackend):
    """Encrypted file-based secrets storage."""

    def __init__(self, secrets_file: Path, password: Optional[str] = None):
        self.secrets_file = Path(secrets_file)
        self.password = password or os.getenv("SECRETS_PASSWORD", "")
        self._cipher_suite: Optional[Fernet] = None
        self._secrets_cache: Optional[Dict[str, str]] = None

    def _get_cipher_suite(self) -> Fernet:
        """Get or create cipher suite for encryption."""
        if self._cipher_suite is None:
            if not self.password:
                raise ConfigurationError(
                    "SECRETS_PASSWORD",
                    "Password required for encrypted secrets file"
                )

            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'witcher_crystal_ball_salt',  # In production, use random salt
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
            self._cipher_suite = Fernet(key)

        return self._cipher_suite

    async def _load_secrets(self) -> Dict[str, str]:
        """Load and decrypt secrets from file."""
        if self._secrets_cache is not None:
            return self._secrets_cache

        if not self.secrets_file.exists():
            logger.info("secrets_file_not_found", path=self.secrets_file)
            self._secrets_cache = {}
            return self._secrets_cache

        try:
            cipher_suite = self._get_cipher_suite()

            with open(self.secrets_file, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = cipher_suite.decrypt(encrypted_data)
            secrets = json.loads(decrypted_data.decode())

            self._secrets_cache = secrets
            logger.debug("secrets_loaded_from_file",
                        path=self.secrets_file,
                        secret_count=len(secrets))

            return secrets

        except Exception as e:
            logger.error("failed_to_load_secrets",
                        path=self.secrets_file,
                        error=str(e))
            raise ConfigurationError(
                "secrets_file",
                f"Failed to load secrets from {self.secrets_file}: {e}"
            )

    async def _save_secrets(self, secrets: Dict[str, str]) -> None:
        """Encrypt and save secrets to file."""
        try:
            # Create secrets directory if it doesn't exist
            self.secrets_file.parent.mkdir(parents=True, exist_ok=True)

            cipher_suite = self._get_cipher_suite()

            data = json.dumps(secrets).encode()
            encrypted_data = cipher_suite.encrypt(data)

            # Write to temporary file first, then move (atomic operation)
            temp_file = self.secrets_file.with_suffix('.tmp')
            with open(temp_file, 'wb') as f:
                f.write(encrypted_data)

            temp_file.replace(self.secrets_file)

            # Set restrictive permissions
            self.secrets_file.chmod(0o600)

            self._secrets_cache = secrets
            logger.debug("secrets_saved_to_file",
                        path=self.secrets_file,
                        secret_count=len(secrets))

        except Exception as e:
            logger.error("failed_to_save_secrets",
                        path=self.secrets_file,
                        error=str(e))
            raise ConfigurationError(
                "secrets_file",
                f"Failed to save secrets to {self.secrets_file}: {e}"
            )

    async def get_secret(self, key: str) -> Optional[str]:
        """Get secret from encrypted file."""
        secrets = await self._load_secrets()
        value = secrets.get(key)

        if value:
            logger.debug("secret_retrieved_from_file", key=key)

        return value

    async def set_secret(self, key: str, value: str) -> None:
        """Store secret in encrypted file."""
        secrets = await self._load_secrets()
        secrets[key] = value
        await self._save_secrets(secrets)
        logger.info("secret_stored_in_file", key=key)

    async def delete_secret(self, key: str) -> None:
        """Delete secret from encrypted file."""
        secrets = await self._load_secrets()
        if key in secrets:
            del secrets[key]
            await self._save_secrets(secrets)
            logger.info("secret_deleted_from_file", key=key)

    def is_available(self) -> bool:
        """Check if encrypted file backend is available."""
        try:
            return bool(self.password)
        except Exception:
            return False


class SecretsManager:
    """
    Unified secrets manager with multiple backend support.

    Tries backends in order of preference:
    1. Encrypted file (if password available)
    2. Environment variables (fallback)
    """

    def __init__(self, backends: Optional[list[SecretsBackend]] = None):
        self.backends = backends or self._default_backends()

        # Find first available backend
        self.active_backend = None
        for backend in self.backends:
            if backend.is_available():
                self.active_backend = backend
                logger.info("secrets_backend_selected",
                           backend=backend.__class__.__name__)
                break

        if not self.active_backend:
            raise ConfigurationError(
                "secrets_backend",
                "No secrets backend available"
            )

    def _default_backends(self) -> list[SecretsBackend]:
        """Create default backends in order of preference."""
        backends = []

        # Try encrypted file first
        secrets_file = Path("data/secrets.enc")
        if os.getenv("SECRETS_PASSWORD"):
            backends.append(EncryptedFileSecretsBackend(secrets_file))

        # Environment variables as fallback
        backends.append(EnvironmentSecretsBackend())

        return backends

    async def get_secret(self, key: str) -> Optional[str]:
        """Get secret from active backend."""
        return await self.active_backend.get_secret(key)

    async def get_secret_required(self, key: str) -> str:
        """Get required secret, raise exception if missing."""
        value = await self.get_secret(key)
        if value is None:
            raise MissingConfigError(key, "secrets")
        return value

    async def set_secret(self, key: str, value: str) -> None:
        """Store secret in active backend."""
        await self.active_backend.set_secret(key, value)

    async def delete_secret(self, key: str) -> None:
        """Delete secret from active backend."""
        await self.active_backend.delete_secret(key)

    def get_backend_info(self) -> Dict[str, Any]:
        """Get information about active backend."""
        return {
            'active_backend': self.active_backend.__class__.__name__,
            'available_backends': [b.__class__.__name__ for b in self.backends if b.is_available()],
            'is_secure': not isinstance(self.active_backend, EnvironmentSecretsBackend)
        }

    async def migrate_from_env(self, env_mappings: Dict[str, str]) -> None:
        """
        Migrate secrets from environment variables to secure storage.

        Args:
            env_mappings: Dict mapping secret keys to environment variable names
        """
        if isinstance(self.active_backend, EnvironmentSecretsBackend):
            logger.warning("cannot_migrate_env_to_env")
            return

        migrated = 0
        for secret_key, env_var in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value:
                await self.set_secret(secret_key, env_value)
                logger.info("secret_migrated",
                           secret_key=secret_key,
                           env_var=env_var)
                migrated += 1

        logger.info("migration_complete", migrated_count=migrated)


# Global secrets manager instance
_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager() -> SecretsManager:
    """Get or create global secrets manager."""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager


async def get_polymarket_private_key() -> str:
    """Get Polymarket private key from secure storage."""
    manager = get_secrets_manager()

    # Try secure storage first
    private_key = await manager.get_secret("polymarket_private_key")

    # Fallback to environment variable for backward compatibility
    if not private_key:
        private_key = await manager.get_secret("POLYMARKET_PRIVATE_KEY")

    if not private_key:
        raise MissingConfigError(
            "polymarket_private_key",
            "Polymarket private key not found in secure storage or environment"
        )

    # Validate private key format
    if not private_key.startswith("0x") or len(private_key) != 66:
        raise ConfigurationError(
            "polymarket_private_key",
            "Invalid private key format (should be 0x followed by 64 hex characters)"
        )

    return private_key


async def get_telegram_bot_token() -> str:
    """Get Telegram bot token from secure storage."""
    manager = get_secrets_manager()

    # Try secure storage first
    token = await manager.get_secret("telegram_bot_token")

    # Fallback to environment variable
    if not token:
        token = await manager.get_secret("TELEGRAM_BOT_TOKEN")

    if not token:
        raise MissingConfigError(
            "telegram_bot_token",
            "Telegram bot token not found in secure storage or environment"
        )

    return token


async def migrate_secrets_from_env() -> None:
    """Migrate all secrets from environment variables to secure storage."""
    manager = get_secrets_manager()

    env_mappings = {
        "polymarket_private_key": "POLYMARKET_PRIVATE_KEY",
        "telegram_bot_token": "TELEGRAM_BOT_TOKEN",
        "telegram_chat_id": "TELEGRAM_CHAT_ID",
    }

    await manager.migrate_from_env(env_mappings)


# Convenience functions for common operations
async def setup_secure_secrets(password: str) -> None:
    """Setup encrypted secrets storage with password."""
    global _secrets_manager

    secrets_file = Path("data/secrets.enc")
    backend = EncryptedFileSecretsBackend(secrets_file, password)
    _secrets_manager = SecretsManager([backend, EnvironmentSecretsBackend()])

    logger.info("secure_secrets_setup", backend="encrypted_file")