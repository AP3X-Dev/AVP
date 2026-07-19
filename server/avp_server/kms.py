"""AWS KMS-backed key loading.

Environment holds only KMS-wrapped DEKs; plaintext DEKs exist in process
memory after KMS Decrypt at startup. Generate wrapped DEKs with
server/scripts/wrap_dek.py.
"""
from __future__ import annotations

from typing import Dict, Optional

import json

from .config import settings
from .crypto import KeyProviderError, LocalEnvKeyProvider, _urlsafe_b64decode_padded


def load_kms_keyring(kms_client=None) -> LocalEnvKeyProvider:
    """Unwrap KMS-wrapped DEKs from settings into a key provider.

    Args:
        kms_client: boto3 KMS client (injectable for tests). Created from
            the default session/credentials chain when None.

    Raises:
        KeyProviderError: on missing config, unwrap failure, or bad key size
    """
    if kms_client is None:
        try:
            import boto3
        except ImportError:
            raise KeyProviderError(
                "AVP_KEY_PROVIDER=aws_kms requires boto3. Install with: pip install 'avp-server[aws]'"
            )
        kms_client = boto3.client("kms")

    wrapped: Dict[str, str] = {}
    if settings.kms_wrapped_keyring_b64.strip():
        try:
            raw_ring = json.loads(settings.kms_wrapped_keyring_b64)
            if not isinstance(raw_ring, dict):
                raise ValueError("must be a JSON object")
            wrapped.update({str(k): str(v) for k, v in raw_ring.items()})
        except Exception as e:
            raise KeyProviderError(f"AVP_KMS_WRAPPED_KEYRING_B64 is invalid: {e}")

    if settings.kms_wrapped_dek_b64.strip():
        wrapped.setdefault(settings.key_version, settings.kms_wrapped_dek_b64)

    if not wrapped:
        raise KeyProviderError(
            "aws_kms provider requires AVP_KMS_WRAPPED_DEK_B64 or AVP_KMS_WRAPPED_KEYRING_B64"
        )

    keyring: Dict[str, bytes] = {}
    for version, b64 in wrapped.items():
        try:
            blob = _urlsafe_b64decode_padded(b64)
        except Exception as e:
            raise KeyProviderError(f"wrapped DEK '{version}' is not valid base64: {e}")

        kwargs = {"CiphertextBlob": blob}
        if settings.kms_key_id:
            kwargs["KeyId"] = settings.kms_key_id
        try:
            resp = kms_client.decrypt(**kwargs)
        except Exception as e:
            raise KeyProviderError(f"KMS decrypt failed for key version '{version}': {e}")

        dek = bytes(resp["Plaintext"])
        if len(dek) != 32:
            raise KeyProviderError(
                f"unwrapped DEK '{version}' is {len(dek)} bytes, expected 32"
            )
        keyring[version] = dek

    if settings.key_version not in keyring:
        raise KeyProviderError(
            f"AVP_KEY_VERSION '{settings.key_version}' not present in wrapped keyring "
            f"(known: {sorted(keyring)})"
        )

    return LocalEnvKeyProvider(
        keyring=keyring,
        key_version=settings.key_version,
        _is_ephemeral=False,
    )
