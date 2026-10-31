"""Cryptographic token encryption and decryption utilities for sensitive credentials."""

import logging
from cryptography.fernet import Fernet, InvalidToken
from app.config import get_settings

logger = logging.getLogger("agentshield.email.crypto")


class TokenCrypto:
    """Handles symmetric authenticated encryption for OAuth access and refresh tokens."""

    def __init__(self, key: bytes = None):
        if key is None:
            settings = get_settings()
            key = settings.get_encryption_key()
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext secret into base64 ciphertext token."""
        if not plaintext:
            return ""
        encrypted_bytes = self._fernet.encrypt(plaintext.encode("utf-8"))
        return encrypted_bytes.decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt base64 ciphertext token into plaintext secret."""
        if not ciphertext:
            return ""
        try:
            decrypted_bytes = self._fernet.decrypt(ciphertext.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except InvalidToken as e:
            logger.error("Failed to decrypt OAuth token: invalid key or corrupted ciphertext")
            raise ValueError("Token decryption failure: Invalid token or encryption key mismatch") from e


_default_crypto = None


def get_token_crypto() -> TokenCrypto:
    """Return singleton instance of TokenCrypto."""
    global _default_crypto
    if _default_crypto is None:
        _default_crypto = TokenCrypto()
    return _default_crypto

