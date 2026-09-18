"""Tests for SecureVault PKCS#7 padding."""

import pytest

from src.crypto.padding import (
    AES_BLOCK_SIZE,
    PaddingError,
    pkcs7_pad,
    pkcs7_unpad,
)


def test_pad_short_message():
    data = b"hello"

    padded = pkcs7_pad(data)

    assert len(padded) % AES_BLOCK_SIZE == 0

    assert pkcs7_unpad(padded) == data


def test_pad_empty_message():
    data = b""

    padded = pkcs7_pad(data)

    assert len(padded) == AES_BLOCK_SIZE

    assert padded == bytes(
        [AES_BLOCK_SIZE]
    ) * AES_BLOCK_SIZE

    assert pkcs7_unpad(padded) == data


def test_full_block_gets_extra_padding_block():
    data = b"A" * AES_BLOCK_SIZE

    padded = pkcs7_pad(data)

    assert len(padded) == (
        AES_BLOCK_SIZE * 2
    )

    assert padded[-AES_BLOCK_SIZE:] == (
        bytes([AES_BLOCK_SIZE])
        * AES_BLOCK_SIZE
    )

    assert pkcs7_unpad(padded) == data


def test_multiple_blocks_round_trip():
    data = (
        b"SecureVault document data "
        b"spanning several blocks."
    )

    padded = pkcs7_pad(data)

    recovered = pkcs7_unpad(
        padded
    )

    assert recovered == data


def test_invalid_padding_length_zero_is_rejected():
    invalid = (
        b"A" * 15
        + b"\x00"
    )

    with pytest.raises(
        PaddingError
    ):
        pkcs7_unpad(invalid)


def test_invalid_padding_too_large_is_rejected():
    invalid = (
        b"A" * 15
        + b"\x11"
    )

    with pytest.raises(
        PaddingError
    ):
        pkcs7_unpad(invalid)


def test_inconsistent_padding_bytes_are_rejected():
    invalid = (
        b"A" * 12
        + b"\x04\x04\x03\x04"
    )

    with pytest.raises(
        PaddingError
    ):
        pkcs7_unpad(invalid)


def test_non_block_aligned_input_is_rejected():
    invalid = b"12345"

    with pytest.raises(
        PaddingError
    ):
        pkcs7_unpad(invalid)


def test_padding_result_is_bytes():
    padded = pkcs7_pad(
        b"SecureVault"
    )

    assert isinstance(
        padded,
        bytes,
    )