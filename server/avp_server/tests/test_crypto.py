import pytest
import os
import base64
import secrets as sec
from unittest.mock import patch, MagicMock

# We need to test crypto module behavior with different settings
# Since the module uses a singleton, we'll test what we can

# Generate a valid test key for tests that need crypto operations
TEST_DEK = sec.token_bytes(32)
TEST_DEK_B64 = base64.urlsafe_b64encode(TEST_DEK).decode()


@pytest.fixture(autouse=True)
def reset_crypto_singleton():
    """Reset the crypto singleton before each test."""
    import server.avp_server.crypto as crypto_module
    crypto_module._key_provider = None
    yield
    crypto_module._key_provider = None


@pytest.fixture
def valid_key_env(monkeypatch):
    """Set up a valid encryption key in the environment."""
    monkeypatch.setenv("AVP_DEK_B64", TEST_DEK_B64)
    monkeypatch.setenv("AVP_DEV_MODE", "true")
    # Reset singleton
    import server.avp_server.crypto as crypto_module
    crypto_module._key_provider = None
    # Reload settings
    from server.avp_server.config import Settings
    crypto_module.settings = Settings()


@pytest.fixture
def dev_ephemeral_env(monkeypatch):
    """Set up dev mode with ephemeral key allowed."""
    monkeypatch.setenv("AVP_DEV_MODE", "true")
    monkeypatch.setenv("AVP_ALLOW_EPHEMERAL_DEK", "true")
    monkeypatch.delenv("AVP_DEK_B64", raising=False)
    # Reset singleton
    import server.avp_server.crypto as crypto_module
    crypto_module._key_provider = None
    # Reload settings
    from server.avp_server.config import Settings
    crypto_module.settings = Settings()


def test_encrypt_decrypt_roundtrip(valid_key_env):
    """Test basic encrypt/decrypt roundtrip works."""
    from server.avp_server.crypto import encrypt_json, decrypt_json

    data = {"api_key": "sk_test", "base_url": "https://example.com"}
    blob = encrypt_json(data)
    out = decrypt_json(blob)
    assert out == data


def test_current_key_version(valid_key_env):
    """Test that current_key_version returns a string."""
    from server.avp_server.crypto import current_key_version
    version = current_key_version()
    assert isinstance(version, str)
    assert len(version) > 0


def test_is_using_ephemeral_key_false_with_valid_key(valid_key_env):
    """Test that is_using_ephemeral_key returns False with valid key."""
    from server.avp_server.crypto import is_using_ephemeral_key
    result = is_using_ephemeral_key()
    assert not result


def test_is_using_ephemeral_key_true_in_dev_mode(dev_ephemeral_env):
    """Test that is_using_ephemeral_key returns True in dev mode with ephemeral."""
    from server.avp_server.crypto import is_using_ephemeral_key
    result = is_using_ephemeral_key()
    assert result


def test_decrypt_json_rejects_short_blob(valid_key_env):
    """Test that decrypt_json rejects blobs shorter than nonce + min ciphertext."""
    from server.avp_server.crypto import decrypt_json

    with pytest.raises(ValueError, match="ciphertext too short"):
        decrypt_json(b"short")


def test_key_provider_error_class():
    """Test that KeyProviderError can be raised and caught."""
    from server.avp_server.crypto import KeyProviderError

    with pytest.raises(KeyProviderError):
        raise KeyProviderError("test error")


class TestLocalEnvKeyProvider:
    """Tests for LocalEnvKeyProvider behavior."""

    def test_valid_key_creates_non_ephemeral_provider(self):
        """Test that valid 32-byte key creates non-ephemeral provider."""
        from server.avp_server.crypto import LocalEnvKeyProvider

        # We can't easily test from_settings due to singleton, but we can test the class directly
        provider = LocalEnvKeyProvider(
            keyring={"test-v1": b"a" * 32},
            key_version="test-v1",
            _is_ephemeral=False
        )

        assert not provider.is_ephemeral
        dek, version = provider.get_current_dek()
        assert len(dek) == 32
        assert version == "test-v1"

    def test_ephemeral_provider_properties(self):
        """Test ephemeral provider behavior."""
        from server.avp_server.crypto import LocalEnvKeyProvider
        import secrets

        provider = LocalEnvKeyProvider(
            keyring={"ephemeral": secrets.token_bytes(32)},
            key_version="ephemeral",
            _is_ephemeral=True
        )

        assert provider.is_ephemeral
        dek, version = provider.get_current_dek()
        assert len(dek) == 32
        assert version == "ephemeral"

    def test_decrypt_with_correct_version(self):
        """Test decrypt_with_key_version with matching version."""
        from server.avp_server.crypto import LocalEnvKeyProvider
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets as sec

        dek = sec.token_bytes(32)
        provider = LocalEnvKeyProvider(keyring={"v1": dek}, key_version="v1", _is_ephemeral=False)

        # Encrypt some data manually
        aesgcm = AESGCM(dek)
        nonce = sec.token_bytes(12)
        plaintext = b"test data"
        ct = aesgcm.encrypt(nonce, plaintext, None)
        blob = nonce + ct

        # Decrypt with provider
        result = provider.decrypt_with_key_version("v1", blob)
        assert result == plaintext

    def test_decrypt_with_wrong_version_raises(self):
        """Test decrypt_with_key_version with mismatched version raises error."""
        from server.avp_server.crypto import LocalEnvKeyProvider, KeyProviderError
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets as sec

        dek = sec.token_bytes(32)
        provider = LocalEnvKeyProvider(keyring={"v1": dek}, key_version="v1", _is_ephemeral=False)

        # Encrypt some data manually
        aesgcm = AESGCM(dek)
        nonce = sec.token_bytes(12)
        plaintext = b"test data"
        ct = aesgcm.encrypt(nonce, plaintext, None)
        blob = nonce + ct

        # Try to decrypt with unknown version - should raise
        with pytest.raises(KeyProviderError, match="no key for version"):
            provider.decrypt_with_key_version("v2", blob)

    def test_keyring_rotation_decrypts_old_versions(self):
        """After rotation, data encrypted under an old key version still decrypts."""
        from server.avp_server.crypto import LocalEnvKeyProvider
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets as sec

        old_dek = sec.token_bytes(32)
        new_dek = sec.token_bytes(32)

        # Encrypt under the old key
        aesgcm = AESGCM(old_dek)
        nonce = sec.token_bytes(12)
        blob = nonce + aesgcm.encrypt(nonce, b"rotated data", None)

        # Provider rotated to v2 but keeps v1 in the keyring
        provider = LocalEnvKeyProvider(
            keyring={"v1": old_dek, "v2": new_dek},
            key_version="v2",
            _is_ephemeral=False
        )

        dek, version = provider.get_current_dek()
        assert version == "v2"
        assert dek == new_dek
        assert provider.decrypt_with_key_version("v1", blob) == b"rotated data"


class TestKeyProviderFromSettings:
    """Tests for from_settings() behavior with different configurations."""

    def test_production_mode_rejects_missing_key(self, monkeypatch):
        """Test that production mode refuses to start without valid key."""
        monkeypatch.setenv("AVP_DEV_MODE", "false")
        monkeypatch.delenv("AVP_DEK_B64", raising=False)

        # Reset singleton and settings
        import server.avp_server.crypto as crypto_module
        from server.avp_server.config import Settings
        crypto_module._key_provider = None
        crypto_module.settings = Settings()

        from server.avp_server.crypto import LocalEnvKeyProvider, KeyProviderError

        with pytest.raises(KeyProviderError, match="Production mode requires valid encryption key"):
            LocalEnvKeyProvider.from_settings()

    def test_production_mode_rejects_invalid_key(self, monkeypatch):
        """Test that production mode rejects key that's not 32 bytes."""
        monkeypatch.setenv("AVP_DEV_MODE", "false")
        monkeypatch.setenv("AVP_DEK_B64", "dG9vc2hvcnQ=")  # "tooshort" base64

        # Reset singleton and settings
        import server.avp_server.crypto as crypto_module
        from server.avp_server.config import Settings
        crypto_module._key_provider = None
        crypto_module.settings = Settings()

        from server.avp_server.crypto import LocalEnvKeyProvider, KeyProviderError

        with pytest.raises(KeyProviderError, match="expected 32"):
            LocalEnvKeyProvider.from_settings()

    def test_dev_mode_without_ephemeral_flag_rejects_missing_key(self, monkeypatch):
        """Test that dev mode without ephemeral flag also rejects missing key."""
        monkeypatch.setenv("AVP_DEV_MODE", "true")
        monkeypatch.setenv("AVP_ALLOW_EPHEMERAL_DEK", "false")
        monkeypatch.delenv("AVP_DEK_B64", raising=False)

        # Reset singleton and settings
        import server.avp_server.crypto as crypto_module
        from server.avp_server.config import Settings
        crypto_module._key_provider = None
        crypto_module.settings = Settings()

        from server.avp_server.crypto import LocalEnvKeyProvider, KeyProviderError

        with pytest.raises(KeyProviderError, match="AVP_ALLOW_EPHEMERAL_DEK=true"):
            LocalEnvKeyProvider.from_settings()

    def test_dev_mode_with_ephemeral_flag_allows_missing_key(self, monkeypatch):
        """Test that dev mode with ephemeral flag allows ephemeral key."""
        monkeypatch.setenv("AVP_DEV_MODE", "true")
        monkeypatch.setenv("AVP_ALLOW_EPHEMERAL_DEK", "true")
        monkeypatch.delenv("AVP_DEK_B64", raising=False)

        # Reset singleton and settings
        import server.avp_server.crypto as crypto_module
        from server.avp_server.config import Settings
        crypto_module._key_provider = None
        crypto_module.settings = Settings()

        from server.avp_server.crypto import LocalEnvKeyProvider

        provider = LocalEnvKeyProvider.from_settings()
        assert provider.is_ephemeral
        assert provider.key_version == "ephemeral"

    def test_valid_key_in_any_mode_works(self, monkeypatch):
        """Test that valid key works in both dev and production mode."""
        valid_key = base64.urlsafe_b64encode(sec.token_bytes(32)).decode()

        for dev_mode in ["true", "false"]:
            monkeypatch.setenv("AVP_DEV_MODE", dev_mode)
            monkeypatch.setenv("AVP_DEK_B64", valid_key)

            # Reset singleton and settings
            import server.avp_server.crypto as crypto_module
            from server.avp_server.config import Settings
            crypto_module._key_provider = None
            crypto_module.settings = Settings()

            from server.avp_server.crypto import LocalEnvKeyProvider

            provider = LocalEnvKeyProvider.from_settings()
            assert not provider.is_ephemeral
            dek, _ = provider.get_current_dek()
            assert len(dek) == 32

    def test_keyring_from_settings(self, monkeypatch):
        """Test that AVP_DEK_KEYRING_B64 configures a multi-version keyring."""
        import json as jsonlib

        k1 = base64.urlsafe_b64encode(sec.token_bytes(32)).decode()
        k2 = base64.urlsafe_b64encode(sec.token_bytes(32)).decode()
        monkeypatch.setenv("AVP_DEK_KEYRING_B64", jsonlib.dumps({"v1": k1, "v2": k2}))
        monkeypatch.setenv("AVP_KEY_VERSION", "v2")
        monkeypatch.delenv("AVP_DEK_B64", raising=False)

        # Reset singleton and settings
        import server.avp_server.crypto as crypto_module
        from server.avp_server.config import Settings
        crypto_module._key_provider = None
        crypto_module.settings = Settings()

        from server.avp_server.crypto import LocalEnvKeyProvider

        provider = LocalEnvKeyProvider.from_settings()
        assert not provider.is_ephemeral
        assert set(provider.keyring) == {"v1", "v2"}
        _, version = provider.get_current_dek()
        assert version == "v2"

    def test_keyring_missing_current_version_rejected(self, monkeypatch):
        """Test that AVP_KEY_VERSION absent from the keyring fails startup."""
        import json as jsonlib
        from server.avp_server.crypto import KeyProviderError

        k1 = base64.urlsafe_b64encode(sec.token_bytes(32)).decode()
        monkeypatch.setenv("AVP_DEK_KEYRING_B64", jsonlib.dumps({"v1": k1}))
        monkeypatch.setenv("AVP_KEY_VERSION", "v9")
        monkeypatch.delenv("AVP_DEK_B64", raising=False)

        import server.avp_server.crypto as crypto_module
        from server.avp_server.config import Settings
        crypto_module._key_provider = None
        crypto_module.settings = Settings()

        from server.avp_server.crypto import LocalEnvKeyProvider

        with pytest.raises(KeyProviderError, match="not present in keyring"):
            LocalEnvKeyProvider.from_settings()
