"""Generate a fresh 32-byte DEK and wrap it with an AWS KMS key.

Prints the environment variables to configure the server with. The plaintext
DEK is never written anywhere.

Usage:
    python server/scripts/wrap_dek.py --kms-key-id alias/avp [--key-version local-2]

Requires boto3 and AWS credentials with kms:Encrypt on the key.
"""
import argparse
import base64
import secrets


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kms-key-id", required=True, help="KMS key id or alias")
    ap.add_argument("--key-version", default="kms-1", help="Version label for this DEK")
    args = ap.parse_args()

    import boto3

    kms = boto3.client("kms")
    dek = secrets.token_bytes(32)
    resp = kms.encrypt(KeyId=args.kms_key_id, Plaintext=dek)
    wrapped = base64.b64encode(resp["CiphertextBlob"]).decode()

    print("# Add to server environment:")
    print("AVP_KEY_PROVIDER=aws_kms")
    print(f"AVP_KMS_KEY_ID={args.kms_key_id}")
    print(f"AVP_KEY_VERSION={args.key_version}")
    print(f"AVP_KMS_WRAPPED_DEK_B64={wrapped}")
    print("# For rotation, use AVP_KMS_WRAPPED_KEYRING_B64 with multiple versions instead.")


if __name__ == "__main__":
    main()
