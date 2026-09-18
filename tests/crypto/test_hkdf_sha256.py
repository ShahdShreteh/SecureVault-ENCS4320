import pytest

from src.crypto.hkdf_sha256 import (
    HKDFError,
    hkdf_expand,
    hkdf_extract,
    hkdf_sha256,
)


def test_rfc5869_case_1_extract():

    ikm = bytes.fromhex(
        "0b" * 22
    )

    salt = bytes.fromhex(
        "000102030405060708090a0b0c"
    )

    expected_prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )

    actual = hkdf_extract(
        salt,
        ikm,
    )

    assert actual == expected_prk


def test_rfc5869_case_1_expand():

    prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )

    info = bytes.fromhex(
        "f0f1f2f3f4f5f6f7f8f9"
    )

    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5b"
        "f34007208d5b887185865"
    )

    actual = hkdf_expand(
        prk,
        info,
        42,
    )

    assert actual == expected


def test_rfc5869_case_1_complete():

    ikm = bytes.fromhex(
        "0b" * 22
    )

    salt = bytes.fromhex(
        "000102030405060708090a0b0c"
    )

    info = bytes.fromhex(
        "f0f1f2f3f4f5f6f7f8f9"
    )

    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5b"
        "f34007208d5b887185865"
    )

    actual = hkdf_sha256(
        ikm,
        salt,
        info,
        42,
    )

    assert actual == expected


def test_same_inputs_produce_same_output():

    first = hkdf_sha256(
        b"shared-secret",
        b"salt",
        b"context",
        64,
    )

    second = hkdf_sha256(
        b"shared-secret",
        b"salt",
        b"context",
        64,
    )

    assert first == second


def test_different_info_changes_output():

    first = hkdf_sha256(
        b"shared-secret",
        b"salt",
        b"context-one",
        32,
    )

    second = hkdf_sha256(
        b"shared-secret",
        b"salt",
        b"context-two",
        32,
    )

    assert first != second


def test_different_salt_changes_output():

    first = hkdf_sha256(
        b"shared-secret",
        b"salt-one",
        b"context",
        32,
    )

    second = hkdf_sha256(
        b"shared-secret",
        b"salt-two",
        b"context",
        32,
    )

    assert first != second


def test_requested_length():

    output = hkdf_sha256(
        b"shared-secret",
        b"salt",
        b"context",
        64,
    )

    assert len(output) == 64


def test_zero_length():

    output = hkdf_sha256(
        b"shared-secret",
        b"salt",
        b"context",
        0,
    )

    assert output == b""


def test_empty_salt_supported():

    output = hkdf_sha256(
        b"shared-secret",
        b"",
        b"context",
        32,
    )

    assert len(output) == 32


def test_too_large_output_rejected():

    with pytest.raises(
        HKDFError
    ):
        hkdf_sha256(
            b"shared-secret",
            b"salt",
            b"context",
            255 * 32 + 1,
        )


def test_negative_length_rejected():

    with pytest.raises(
        HKDFError
    ):
        hkdf_sha256(
            b"shared-secret",
            b"salt",
            b"context",
            -1,
        )


def test_input_key_material_must_be_bytes():

    with pytest.raises(
        TypeError
    ):
        hkdf_sha256(
            "shared-secret",
            b"salt",
            b"context",
            32,
        )


def test_salt_must_be_bytes():

    with pytest.raises(
        TypeError
    ):
        hkdf_sha256(
            b"shared-secret",
            "salt",
            b"context",
            32,
        )


def test_info_must_be_bytes():

    with pytest.raises(
        TypeError
    ):
        hkdf_sha256(
            b"shared-secret",
            b"salt",
            "context",
            32,
        )