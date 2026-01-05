"""
Sentinel-Zero Cryptography Utilities

Secure encryption/decryption for:
- Credential storage
- Sensitive configuration
- PII protection in database
- API token generation

Uses industry-standard Fernet (AES-128 CBC + HMAC SHA256)
with secure key derivation.

Copyright (c) 2024 Sentinel Security Inc.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

from config import get_settings
from utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class EncryptionError(Exception):
    """Base exception for encryption operations."""
    pass


class DecryptionError(Exception):
    """Base exception for decryption operations."""
    pass


class CryptoManager:
    """
    Central cryptographic operations manager.

    Handles encryption, decryption, hashing, and secure token generation
    using best practices and industry standards.
    """

    def __init__(self):
        """Initialize with application encryption key."""
        key = settings.security.encryption_key.get_secret_value()
        self._fernet = Fernet(key.encode())

    def encrypt(self, plaintext: str | bytes) -> str:
        """
        Encrypt data using Fernet (AES-128).

        Args:
            plaintext: Data to encrypt (string or bytes)

        Returns:
            Base64-encoded encrypted data

        Raises:
            EncryptionError: If encryption fails
        """
        try:
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')

            encrypted = self._fernet.encrypt(plaintext)
            return base64.urlsafe_b64encode(encrypted).decode('utf-8')

        except Exception as e:
            logger.error("Encryption failed", error=str(e))
            raise EncryptionError(f"Failed to encrypt data: {e}")

    def decrypt(self, encrypted_data: str | bytes) -> str:
        """
        Decrypt Fernet-encrypted data.

        Args:
            encrypted_data: Base64-encoded encrypted data

        Returns:
            Decrypted plaintext as string

        Raises:
            DecryptionError: If decryption fails or data is invalid
        """
        try:
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode('utf-8')

            decoded = base64.urlsafe_b64decode(encrypted_data)
            decrypted = self._fernet.decrypt(decoded)
            return decrypted.decode('utf-8')

        except InvalidToken:
            logger.error("Invalid encryption token during decryption")
            raise DecryptionError("Invalid or corrupted encrypted data")
        except Exception as e:
            logger.error("Decryption failed", error=str(e))
            raise DecryptionError(f"Failed to decrypt data: {e}")

    def encrypt_dict(self, data: dict[str, Any]) -> str:
        """
        Encrypt a dictionary as JSON.

        Useful for storing structured sensitive data.
        """
        import json
        json_str = json.dumps(data, default=str)
        return self.encrypt(json_str)

    def decrypt_dict(self, encrypted_data: str) -> dict[str, Any]:
        """
        Decrypt and parse JSON dictionary.
        """
        import json
        json_str = self.decrypt(encrypted_data)
        return json.loads(json_str)

    @staticmethod
    def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
        """
        Hash a password using PBKDF2-HMAC-SHA256.

        Args:
            password: Plain text password
            salt: Optional salt (generated if not provided)

        Returns:
            Tuple of (hashed_password, salt) as base64 strings
        """
        if salt is None:
            salt = secrets.token_bytes(32)

        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,  # OWASP recommendation 2023
        )

        key = kdf.derive(password.encode('utf-8'))

        hashed = base64.b64encode(key).decode('utf-8')
        salt_b64 = base64.b64encode(salt).decode('utf-8')

        return hashed, salt_b64

    @staticmethod
    def verify_password(password: str, hashed: str, salt: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            password: Plain text password to verify
            hashed: Base64-encoded password hash
            salt: Base64-encoded salt

        Returns:
            True if password matches, False otherwise
        """
        try:
            salt_bytes = base64.b64decode(salt.encode('utf-8'))
            expected_hash, _ = CryptoManager.hash_password(password, salt_bytes)
            return secrets.compare_digest(expected_hash, hashed)
        except Exception as e:
            logger.error("Password verification failed", error=str(e))
            return False

    @staticmethod
    def generate_api_key(prefix: str = "sk", length: int = 32) -> str:
        """
        Generate a cryptographically secure API key.

        Args:
            prefix: Key prefix for identification (e.g., 'sk', 'pk')
            length: Number of random bytes

        Returns:
            API key in format: prefix_base64randomdata
        """
        random_bytes = secrets.token_bytes(length)
        random_str = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
        return f"{prefix}_{random_str}"

    @staticmethod
    def generate_token(nbytes: int = 32) -> str:
        """
        Generate a random token for sessions, CSRF, etc.

        Args:
            nbytes: Number of random bytes

        Returns:
            URL-safe base64 token
        """
        return secrets.token_urlsafe(nbytes)

    @staticmethod
    def hash_file(file_data: bytes, algorithm: str = 'sha256') -> str:
        """
        Calculate file hash for integrity verification.

        Args:
            file_data: File content as bytes
            algorithm: Hash algorithm ('sha256', 'sha512', 'md5')

        Returns:
            Hex-encoded hash digest
        """
        if algorithm == 'sha256':
            hasher = hashlib.sha256()
        elif algorithm == 'sha512':
            hasher = hashlib.sha512()
        elif algorithm == 'md5':
            hasher = hashlib.md5()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        hasher.update(file_data)
        return hasher.hexdigest()

    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """
        Timing-safe string comparison.

        Prevents timing attacks when comparing secrets.
        """
        return secrets.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


class JWTManager:
    """
    JSON Web Token manager for API authentication.

    Creates and verifies JWT tokens with configurable expiration.
    """

    def __init__(self):
        """Initialize with application secret key."""
        self.secret_key = settings.security.api_secret_key.get_secret_value()
        self.algorithm = settings.security.jwt_algorithm
        self.expiration_hours = settings.security.jwt_expiration_hours

    def create_token(
            self,
            subject: str,
            additional_claims: dict[str, Any] | None = None,
            expires_delta: timedelta | None = None,
    ) -> str:
        """
        Create a JWT token.

        Args:
            subject: Token subject (typically user ID)
            additional_claims: Extra data to include in token
            expires_delta: Custom expiration time

        Returns:
            Encoded JWT token
        """
        from jose import jwt

        if expires_delta is None:
            expires_delta = timedelta(hours=self.expiration_hours)

        expire = datetime.utcnow() + expires_delta

        claims = {
            'sub': subject,
            'exp': expire,
            'iat': datetime.utcnow(),
            'iss': 'sentinel-zero',
        }

        if additional_claims:
            claims.update(additional_claims)

        token = jwt.encode(claims, self.secret_key, algorithm=self.algorithm)
        return token

    def verify_token(self, token: str) -> dict[str, Any]:
        """
        Verify and decode a JWT token.

        Args:
            token: JWT token to verify

        Returns:
            Decoded token claims

        Raises:
            DecryptionError: If token is invalid or expired
        """
        from jose import jwt, JWTError

        try:
            claims = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                },
            )
            return claims

        except JWTError as e:
            logger.warning("JWT verification failed", error=str(e))
            raise DecryptionError(f"Invalid token: {e}")


# Global instances
crypto = CryptoManager()
jwt_manager = JWTManager()


def encrypt(data: str | bytes) -> str:
    """Convenience function for encryption."""
    return crypto.encrypt(data)


def decrypt(encrypted_data: str | bytes) -> str:
    """Convenience function for decryption."""
    return crypto.decrypt(encrypted_data)


def generate_encryption_key() -> str:
    """
    Generate a new Fernet encryption key.

    Use this to generate the ENCRYPTION_KEY for .env file.
    Run once and store securely.
    """
    key = Fernet.generate_key()
    return key.decode('utf-8')


# Convenience exports
__all__ = [
    'CryptoManager',
    'JWTManager',
    'crypto',
    'jwt_manager',
    'encrypt',
    'decrypt',
    'generate_encryption_key',
    'EncryptionError',
    'DecryptionError',
]