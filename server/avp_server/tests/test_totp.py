"""TOTP minting, checked against the RFC 6238 published test vectors.

The vectors matter more than a round-trip test would: they prove this agrees
with every authenticator app in the world, rather than merely agreeing with
itself. The security property under test at the bottom is that the seed cannot
be extracted through secret resolution.
"""
import asyncio

import pytest

from avp_server.services.registry import (
    SecretValidationError,
    get_service_spec,
    format_env,
    operation_allowed,
)
from avp_server.services.totp import (
    TotpError,
    decode_seed,
    generate,
    seconds_remaining,
    totp_code,
)

# RFC 6238 Appendix B: the ASCII seed "12345678901234567890", base32-encoded.
RFC_SEED_SHA1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
# SHA256 uses a 32-byte seed, SHA512 a 64-byte one (the ASCII string repeated).
RFC_SEED_SHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
RFC_SEED_SHA512 = (
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="
)


@pytest.mark.parametrize(
    "timestamp,expected",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_rfc6238_sha1_vectors(timestamp, expected):
    assert generate(RFC_SEED_SHA1, digits=8, algorithm="SHA1", timestamp=timestamp) == expected


@pytest.mark.parametrize(
    "timestamp,expected",
    [
        (59, "46119246"),
        (1111111109, "68084774"),
        (2000000000, "90698825"),
    ],
)
def test_rfc6238_sha256_vectors(timestamp, expected):
    assert generate(RFC_SEED_SHA256, digits=8, algorithm="SHA256", timestamp=timestamp) == expected


@pytest.mark.parametrize(
    "timestamp,expected",
    [
        (59, "90693936"),
        (1111111109, "25091201"),
        (2000000000, "38618901"),
    ],
)
def test_rfc6238_sha512_vectors(timestamp, expected):
    assert generate(RFC_SEED_SHA512, digits=8, algorithm="SHA512", timestamp=timestamp) == expected


def test_six_digit_default_is_the_last_six_of_the_eight_digit_vector():
    # Truncation is modulo 10**digits, so the 6-digit code is the 8-digit one's tail.
    assert generate(RFC_SEED_SHA1, timestamp=59) == "287082"


def test_code_is_stable_within_a_period_and_changes_across_it():
    # Windows are counter = floor(t / 30), so they break at multiples of 30:
    # 90-119 is one window, 120-149 the next.
    assert generate(RFC_SEED_SHA1, timestamp=90) == generate(RFC_SEED_SHA1, timestamp=119)
    assert generate(RFC_SEED_SHA1, timestamp=119) != generate(RFC_SEED_SHA1, timestamp=120)


def test_seed_decoding_tolerates_human_formatting():
    # Authenticator UIs print seeds spaced and lowercase, unpadded.
    canonical = decode_seed(RFC_SEED_SHA1)
    assert decode_seed("gezd gnbv gy3t qojq gezd gnbv gy3t qojq") == canonical
    assert decode_seed("GEZDGNBV-GY3TQOJQ-GEZDGNBV-GY3TQOJQ") == canonical


def test_seed_decoding_rejects_junk():
    with pytest.raises(TotpError):
        decode_seed("not-base32-!!")
    with pytest.raises(TotpError):
        decode_seed("   ")


def test_generate_rejects_out_of_range_parameters():
    with pytest.raises(TotpError):
        generate(RFC_SEED_SHA1, digits=4)
    with pytest.raises(TotpError):
        generate(RFC_SEED_SHA1, digits=11)
    with pytest.raises(TotpError):
        generate(RFC_SEED_SHA1, period=0)
    with pytest.raises(TotpError):
        generate(RFC_SEED_SHA1, algorithm="MD5")


def test_seconds_remaining_counts_down_within_the_window():
    assert seconds_remaining(30, timestamp=0) == 30
    assert seconds_remaining(30, timestamp=1) == 29
    assert seconds_remaining(30, timestamp=29) == 1


# --- adapter -----------------------------------------------------------------


def _call(secret_data, payload=None):
    return asyncio.run(totp_code(secret_data, payload or {}))


def test_adapter_returns_code_and_validity_window():
    status, data = _call({"seed": RFC_SEED_SHA1})
    assert status == 200
    assert data["code"].isdigit() and len(data["code"]) == 6
    assert 1 <= data["expires_in"] <= 30
    assert data["period"] == 30 and data["digits"] == 6


def test_adapter_never_echoes_the_seed():
    _status, data = _call({"seed": RFC_SEED_SHA1, "label": "github"})
    assert RFC_SEED_SHA1 not in str(data)
    assert "seed" not in data


def test_adapter_honors_stored_parameters_including_numeric_strings():
    status, data = _call({"seed": RFC_SEED_SHA1, "digits": 8, "period": 60})
    assert status == 200 and len(data["code"]) == 8 and data["period"] == 60
    # A credential round-tripped through JSON may carry these as strings.
    status, data = _call({"seed": RFC_SEED_SHA1, "digits": "8", "period": "60"})
    assert status == 200 and len(data["code"]) == 8 and data["period"] == 60


def test_adapter_ignores_a_caller_supplied_timestamp():
    # Accepting one would let an agent mint codes for any point in time, undoing
    # the whole point of a 30-second credential. Two payloads asking for wildly
    # different moments must both answer for *now*.
    _status, past = _call({"seed": RFC_SEED_SHA1}, {"timestamp": 59})
    _status, future = _call({"seed": RFC_SEED_SHA1}, {"timestamp": 20000000000})
    assert past["code"] == future["code"] == generate(RFC_SEED_SHA1)
    # 59 and 20000000000 are the RFC vector times; neither may be honoured.
    assert past["code"] not in ("287082", "353130")


def test_adapter_reports_a_broken_credential_as_a_server_fault():
    status, data = _call({})
    assert status == 500 and "seed" in data["error"]["message"]
    status, data = _call({"seed": "!!!"})
    assert status == 500 and data["error"]["type"] == "server_error"
    status, data = _call({"seed": RFC_SEED_SHA1, "digits": "many"})
    assert status == 500


# --- registry wiring ---------------------------------------------------------


def test_totp_is_registered_with_a_code_operation():
    spec = get_service_spec("totp")
    assert spec is not None
    assert spec.operations == {"code": "code"}
    assert operation_allowed("totp", "code", ["code"]) is True
    assert operation_allowed("totp", "code", ["chat"]) is False


def test_totp_credential_requires_a_seed_and_types_its_parameters():
    spec = get_service_spec("totp")
    spec.validate_secret({"seed": RFC_SEED_SHA1})
    spec.validate_secret({"seed": RFC_SEED_SHA1, "digits": 8, "period": 60})
    with pytest.raises(SecretValidationError):
        spec.validate_secret({"label": "no seed here"})
    with pytest.raises(SecretValidationError):
        spec.validate_secret({"seed": RFC_SEED_SHA1, "digits": "8"})
    # bool is a subclass of int; it must not pass as one.
    with pytest.raises(SecretValidationError):
        spec.validate_secret({"seed": RFC_SEED_SHA1, "digits": True})


def test_totp_material_is_not_resolvable():
    """The security property: no grant can turn the seed into resolved material."""
    assert get_service_spec("totp").resolvable is False
    # Every other service stays resolvable — this is opt-in, not a global change.
    assert get_service_spec("openai").resolvable is True
    assert get_service_spec("anthropic").resolvable is True


def test_totp_env_mapping_is_empty_so_no_formatting_path_leaks_it():
    assert get_service_spec("totp").env_mapping == {}
    assert format_env("totp", {"seed": RFC_SEED_SHA1}) == {}
