"""TOTP (RFC 6238) minting as a vault-mediated operation.

A TOTP seed is a long-lived secret whose only purpose is deriving a short-lived
six-digit code. Handing the seed to an agent gives it the ability to mint codes
forever, on any machine, long after its session is revoked — which is precisely
what proxy mode exists to prevent. So the `totp` service mints the code inside
the vault and returns only that: the seed never crosses the wire.

The seed is additionally marked non-resolvable in the service registry, so no
capability grant can hand it over through `resolve_secrets` either.

Implemented on the standard library (hmac/hashlib/base64) — no new dependency
for what is thirty lines of RFC 4226.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import struct
import time
from typing import Any, Dict, Tuple

#: Hash algorithms RFC 6238 permits, by their canonical spelling.
ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
DEFAULT_ALGORITHM = "SHA1"

# Authenticator seeds are shown to humans in groups ("JBSW Y3DP …") and get
# pasted back with the spacing intact, so strip separators before decoding.
_SEPARATORS = re.compile(r"[\s-]+")


class TotpError(ValueError):
    """The stored credential cannot produce a code (bad seed or parameters)."""


def decode_seed(seed: str) -> bytes:
    """Decode a base32 authenticator seed, tolerating case, spacing and missing padding."""
    cleaned = _SEPARATORS.sub("", seed).upper()
    if not cleaned:
        raise TotpError("seed is empty")
    # b32decode demands the input be a multiple of 8 chars; authenticator seeds
    # are routinely published without their trailing '='.
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(cleaned, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise TotpError(f"seed is not valid base32: {exc}") from exc


def generate(
    seed: str,
    *,
    digits: int = DEFAULT_DIGITS,
    period: int = DEFAULT_PERIOD,
    algorithm: str = DEFAULT_ALGORITHM,
    timestamp: float | None = None,
) -> str:
    """Return the TOTP code for `timestamp` (default: now). RFC 6238 §4."""
    if digits < 6 or digits > 10:
        raise TotpError(f"digits must be between 6 and 10, got {digits}")
    if period < 1:
        raise TotpError(f"period must be positive, got {period}")
    hashfunc = ALGORITHMS.get(str(algorithm).upper().replace("-", ""))
    if hashfunc is None:
        raise TotpError(f"unsupported algorithm {algorithm!r}; expected one of {sorted(ALGORITHMS)}")

    now = time.time() if timestamp is None else timestamp
    counter = int(now // period)
    digest = hmac.new(decode_seed(seed), struct.pack(">Q", counter), hashfunc).digest()

    # Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte picks
    # the 4-byte window; the top bit is cleared to dodge sign ambiguity.
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def seconds_remaining(period: int = DEFAULT_PERIOD, timestamp: float | None = None) -> int:
    """Whole seconds the current code stays valid — lets a caller decide whether
    to use this code or wait for the next window rather than race the boundary."""
    now = time.time() if timestamp is None else timestamp
    return int(period - (now % period))


def _int_field(secret_data: Dict[str, Any], key: str, default: int) -> int:
    """Read an optional integer parameter, accepting the numeric string form a
    JSON credential often ends up carrying."""
    raw = secret_data.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise TotpError(f"{key} must be an integer, got {raw!r}") from exc


async def totp_code(secret_data: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Proxy adapter for `totp.code`.

    Deliberately ignores `payload`: accepting a caller-supplied timestamp would
    let an agent mint codes for arbitrary points in time, turning a 30-second
    credential back into an unbounded one.
    """
    seed = secret_data.get("seed")
    if not seed:
        return 500, {"error": {"message": "missing seed in secret", "type": "server_error"}}

    try:
        digits = _int_field(secret_data, "digits", DEFAULT_DIGITS)
        period = _int_field(secret_data, "period", DEFAULT_PERIOD)
        algorithm = secret_data.get("algorithm") or DEFAULT_ALGORITHM
        code = generate(seed, digits=digits, period=period, algorithm=algorithm)
    except TotpError as exc:
        # The stored credential is wrong, not the request — surface it as a
        # server-side fault so the agent does not retry a doomed call.
        return 500, {"error": {"message": str(exc), "type": "server_error"}}

    return 200, {
        "code": code,
        "expires_in": seconds_remaining(period),
        "period": period,
        "digits": digits,
    }
