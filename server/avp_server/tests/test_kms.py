"""Tests for the AWS KMS key provider (fake KMS client, no AWS needed)."""
import base64
import json
import secrets as sec

import pytest


class FakeKMSClient:
    """Pretends every ciphertext is base64(plaintext) prefixed with b'wrapped:'."""

    def __init__(self):
        self.calls = []

    @staticmethod
    def wrap(plaintext: bytes) -> bytes:
        return b"wrapped:" + plaintext

    def decrypt(self, CiphertextBlob: bytes, **kwargs):
        self.calls.append(kwargs)
        assert CiphertextBlob.startswith(b"wrapped:")
        return {"Plaintext": CiphertextBlob[len(b"wrapped:"):]}


class FailingKMSClient:
    def decrypt(self, **kwargs):
        raise RuntimeError("kms unavailable")


def _configure(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import server.avp_server.kms as kms_module
    from server.avp_server.config import Settings
    kms_module.settings = Settings()
    return kms_module


def test_unwraps_single_dek(monkeypatch):
    dek = sec.token_bytes(32)
    wrapped_b64 = base64.b64encode(FakeKMSClient.wrap(dek)).decode()
    kms_module = _configure(
        monkeypatch,
        AVP_KEY_PROVIDER="aws_kms",
        AVP_KEY_VERSION="kms-1",
        AVP_KMS_WRAPPED_DEK_B64=wrapped_b64,
        AVP_KMS_WRAPPED_KEYRING_B64="",
    )

    provider = kms_module.load_kms_keyring(kms_client=FakeKMSClient())
    got_dek, version = provider.get_current_dek()
    assert version == "kms-1"
    assert got_dek == dek
    assert not provider.is_ephemeral


def test_unwraps_keyring_for_rotation(monkeypatch):
    old_dek = sec.token_bytes(32)
    new_dek = sec.token_bytes(32)
    ring = {
        "kms-1": base64.b64encode(FakeKMSClient.wrap(old_dek)).decode(),
        "kms-2": base64.b64encode(FakeKMSClient.wrap(new_dek)).decode(),
    }
    kms_module = _configure(
        monkeypatch,
        AVP_KEY_PROVIDER="aws_kms",
        AVP_KEY_VERSION="kms-2",
        AVP_KMS_WRAPPED_DEK_B64="",
        AVP_KMS_WRAPPED_KEYRING_B64=json.dumps(ring),
    )

    provider = kms_module.load_kms_keyring(kms_client=FakeKMSClient())
    assert set(provider.keyring) == {"kms-1", "kms-2"}
    _, version = provider.get_current_dek()
    assert version == "kms-2"
    assert provider.keyring["kms-1"] == old_dek


def test_missing_config_rejected(monkeypatch):
    kms_module = _configure(
        monkeypatch,
        AVP_KEY_PROVIDER="aws_kms",
        AVP_KMS_WRAPPED_DEK_B64="",
        AVP_KMS_WRAPPED_KEYRING_B64="",
    )
    from server.avp_server.crypto import KeyProviderError

    with pytest.raises(KeyProviderError, match="requires AVP_KMS_WRAPPED"):
        kms_module.load_kms_keyring(kms_client=FakeKMSClient())


def test_kms_failure_surfaces_as_key_provider_error(monkeypatch):
    wrapped_b64 = base64.b64encode(FakeKMSClient.wrap(sec.token_bytes(32))).decode()
    kms_module = _configure(
        monkeypatch,
        AVP_KEY_PROVIDER="aws_kms",
        AVP_KEY_VERSION="kms-1",
        AVP_KMS_WRAPPED_DEK_B64=wrapped_b64,
        AVP_KMS_WRAPPED_KEYRING_B64="",
    )
    from server.avp_server.crypto import KeyProviderError

    with pytest.raises(KeyProviderError, match="KMS decrypt failed"):
        kms_module.load_kms_keyring(kms_client=FailingKMSClient())


def test_wrong_dek_size_rejected(monkeypatch):
    wrapped_b64 = base64.b64encode(FakeKMSClient.wrap(b"short")).decode()
    kms_module = _configure(
        monkeypatch,
        AVP_KEY_PROVIDER="aws_kms",
        AVP_KEY_VERSION="kms-1",
        AVP_KMS_WRAPPED_DEK_B64=wrapped_b64,
        AVP_KMS_WRAPPED_KEYRING_B64="",
    )
    from server.avp_server.crypto import KeyProviderError

    with pytest.raises(KeyProviderError, match="expected 32"):
        kms_module.load_kms_keyring(kms_client=FakeKMSClient())


def test_key_id_passed_to_kms(monkeypatch):
    dek = sec.token_bytes(32)
    wrapped_b64 = base64.b64encode(FakeKMSClient.wrap(dek)).decode()
    kms_module = _configure(
        monkeypatch,
        AVP_KEY_PROVIDER="aws_kms",
        AVP_KEY_VERSION="kms-1",
        AVP_KMS_KEY_ID="alias/avp",
        AVP_KMS_WRAPPED_DEK_B64=wrapped_b64,
        AVP_KMS_WRAPPED_KEYRING_B64="",
    )

    client = FakeKMSClient()
    kms_module.load_kms_keyring(kms_client=client)
    assert client.calls == [{"KeyId": "alias/avp"}]
