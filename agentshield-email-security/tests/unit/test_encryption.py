"""Unit tests for TokenCrypto token encryption at rest."""

import pytest
from app.security.token_crypto import TokenCrypto


def test_encrypt_and_decrypt_cycle():
    crypto = TokenCrypto()
    secret_token = "ya29.a0AfH6SMB_secret_oauth_access_token_12345"

    ciphertext = crypto.encrypt(secret_token)
    assert ciphertext != secret_token
    assert len(ciphertext) > len(secret_token)

    decrypted = crypto.decrypt(ciphertext)
    assert decrypted == secret_token


def test_empty_token_handling():
    crypto = TokenCrypto()
    assert crypto.encrypt("") == ""
    assert crypto.decrypt("") == ""


def test_tampered_token_fails_gracefully():
    crypto = TokenCrypto()
    ciphertext = crypto.encrypt("my-refresh-token")

    # Tamper with the ciphertext string
    tampered = ciphertext[:-4] + "AAAA"

    with pytest.raises(ValueError) as exc:
        crypto.decrypt(tampered)
    assert "decryption failure" in str(exc.value)

